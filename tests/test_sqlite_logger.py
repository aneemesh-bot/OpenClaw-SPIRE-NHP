"""Tests for the SQLite-based structured logger."""

import time

from nhp_daemon.sqlite_logger import LogLevel, SQLiteLogger


class TestSQLiteLogger:
    def test_create_and_query(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        logger.info("test", "hello world", metadata={"key": "val"})

        rows = logger.query(component="test")
        assert len(rows) == 1
        assert rows[0][4] == "hello world"  # message column
        logger.close()

    def test_log_levels(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        logger.debug("c", "d")
        logger.info("c", "i")
        logger.warning("c", "w")
        logger.error("c", "e")
        logger.critical("c", "cr")

        rows = logger.query(component="c", limit=10)
        assert len(rows) == 5
        logger.close()

    def test_query_by_level(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        logger.info("c", "info msg")
        logger.error("c", "error msg")

        errors = logger.query(level=LogLevel.ERROR)
        assert len(errors) == 1
        assert errors[0][4] == "error msg"
        logger.close()

    def test_query_since(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        ts = time.time()
        logger.info("c", "recent")

        rows = logger.query(since=ts - 1)
        assert len(rows) >= 1
        logger.close()

    def test_spiffe_id_and_event_type(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        logger.info(
            "server",
            "minted",
            spiffe_id="spiffe://test/agent",
            event_type="svid_minted",
        )

        rows = logger.query(component="server")
        assert len(rows) == 1
        assert rows[0][6] == "spiffe://test/agent"   # spiffe_id column
        assert rows[0][7] == "svid_minted"            # event_type column
        logger.close()

    def test_metadata_json(self, tmp_path):
        logger = SQLiteLogger(str(tmp_path / "log.db"))
        logger.info("c", "m", metadata={"ttl": 300, "serial": "abc"})

        rows = logger.query(component="c")
        import json
        meta = json.loads(rows[0][5])
        assert meta["ttl"] == 300
        assert meta["serial"] == "abc"
        logger.close()
