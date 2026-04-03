"""Shared fixtures for SPIRE NHP tests."""

import os
import pytest

from nhp_daemon.ca import CertificateAuthority
from nhp_daemon.registration import RegistrationStore
from nhp_daemon.spire_server import SPIREServer
from nhp_daemon.sqlite_logger import SQLiteLogger
from nhp_daemon.tpm_simulator import TPMSimulator
from nhp_daemon.trust_bundle import TrustBundle

TRUST_DOMAIN = "test.example.com"


@pytest.fixture
def logger(tmp_path):
    lg = SQLiteLogger(str(tmp_path / "test_log.db"))
    yield lg
    lg.close()


@pytest.fixture
def ca():
    return CertificateAuthority(TRUST_DOMAIN)


@pytest.fixture
def tpm():
    return TPMSimulator()


@pytest.fixture
def trust_bundle(ca):
    bundle = TrustBundle(
        trust_domain=TRUST_DOMAIN,
        root_certificate=ca.root_certificate,
    )
    bundle.add_signing_key(ca.public_key_pem)
    return bundle


@pytest.fixture
def registration_store(tmp_path):
    return RegistrationStore(str(tmp_path / "test_reg.db"))


@pytest.fixture
def server(tmp_path, logger):
    return SPIREServer(TRUST_DOMAIN, str(tmp_path / "server.db"), logger)
