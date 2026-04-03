"""Tests for workload attestation helpers."""

from nhp_daemon.attestation import PeerInfo, WorkloadAttestor


class TestWorkloadAttestor:
    def test_build_selectors_uid_only(self):
        peer = PeerInfo(pid=1234, uid=1001, gid=100)
        selectors = WorkloadAttestor.build_selectors_from_peer(peer)
        assert ("unix", "uid:1001") in selectors
        assert len(selectors) == 1

    def test_build_selectors_with_hash(self):
        peer = PeerInfo(pid=1234, uid=1001, gid=100, binary_hash="abc123")
        selectors = WorkloadAttestor.build_selectors_from_peer(peer)
        assert ("unix", "uid:1001") in selectors
        assert ("unix", "sha256:abc123") in selectors
        assert len(selectors) == 2

    def test_hash_binary(self, tmp_path):
        f = tmp_path / "bin"
        f.write_bytes(b"test content")
        h = WorkloadAttestor._hash_binary(str(f))
        assert len(h) == 64

    def test_hash_binary_missing(self):
        h = WorkloadAttestor._hash_binary("/nonexistent/binary")
        assert h == ""
