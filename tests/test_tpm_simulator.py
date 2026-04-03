"""Tests for the simulated TPM."""

from nhp_daemon.tpm_simulator import TPMSimulator


class TestTPMSimulator:
    def test_endorsement_key(self, tpm):
        assert len(tpm.endorsement_key_hash) == 64  # SHA-256 hex

    def test_unique_endorsement_keys(self):
        a = TPMSimulator()
        b = TPMSimulator()
        assert a.endorsement_key_hash != b.endorsement_key_hash

    def test_measure_binary(self, tpm, tmp_path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"ELF fake binary content")
        measurement = tpm.measure_binary(str(binary))
        assert len(measurement) == 64
        assert tpm.get_pcr(0) == measurement

    def test_measure_missing_binary(self, tpm):
        measurement = tpm.measure_binary("/nonexistent/path")
        assert len(measurement) == 64  # falls back to hashing the path

    def test_generate_key_pair(self, tpm):
        priv, pub = tpm.generate_key_pair()
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    def test_quote(self, tpm, tmp_path):
        binary = tmp_path / "bin"
        binary.write_bytes(b"data")
        tpm.measure_binary(str(binary))

        quote = tpm.quote([0], nonce=b"nonce123")
        assert quote["simulated"] is True
        assert 0 in quote["pcr_values"]
        assert quote["pcr_values"][0] is not None
