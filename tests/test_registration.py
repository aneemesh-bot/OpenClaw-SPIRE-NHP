"""Tests for the Registration Store."""

from nhp_daemon.registration import RegistrationEntry, RegistrationStore, Selector


class TestRegistrationStore:
    def test_create_and_get(self, registration_store):
        entry = RegistrationEntry(
            spiffe_id="spiffe://test/agent",
            parent_id="spiffe://test/node",
            selectors=[Selector(type="unix", value="uid:1000")],
            ttl=300,
        )
        eid = registration_store.create_entry(entry)
        fetched = registration_store.get_entry(eid)
        assert fetched is not None
        assert fetched.spiffe_id == "spiffe://test/agent"
        assert fetched.ttl == 300

    def test_list_entries(self, registration_store):
        for i in range(3):
            registration_store.create_entry(
                RegistrationEntry(
                    spiffe_id=f"spiffe://test/agent-{i}",
                    parent_id="spiffe://test/node",
                    selectors=[Selector(type="unix", value=f"uid:{1000 + i}")],
                )
            )
        assert len(registration_store.list_entries()) == 3

    def test_delete_entry(self, registration_store):
        entry = RegistrationEntry(
            spiffe_id="spiffe://test/del",
            parent_id="spiffe://test/node",
            selectors=[Selector(type="unix", value="uid:9999")],
        )
        eid = registration_store.create_entry(entry)
        assert registration_store.delete_entry(eid) is True
        assert registration_store.get_entry(eid) is None

    def test_delete_nonexistent(self, registration_store):
        assert registration_store.delete_entry("no-such-id") is False

    def test_find_by_selectors_exact_match(self, registration_store):
        registration_store.create_entry(
            RegistrationEntry(
                spiffe_id="spiffe://test/match",
                parent_id="spiffe://test/node",
                selectors=[Selector(type="unix", value="uid:1001")],
            )
        )
        results = registration_store.find_by_selectors(
            [Selector(type="unix", value="uid:1001")]
        )
        assert len(results) == 1
        assert results[0].spiffe_id == "spiffe://test/match"

    def test_find_by_selectors_partial_does_not_match(self, registration_store):
        """Entry requires uid AND sha256 — workload presenting only uid must NOT match."""
        registration_store.create_entry(
            RegistrationEntry(
                spiffe_id="spiffe://test/strict",
                parent_id="spiffe://test/node",
                selectors=[
                    Selector(type="unix", value="uid:1001"),
                    Selector(type="unix", value="sha256:abc123"),
                ],
            )
        )
        results = registration_store.find_by_selectors(
            [Selector(type="unix", value="uid:1001")]
        )
        assert len(results) == 0

    def test_find_by_selectors_superset_matches(self, registration_store):
        """Workload presenting MORE attributes than required should still match."""
        registration_store.create_entry(
            RegistrationEntry(
                spiffe_id="spiffe://test/ok",
                parent_id="spiffe://test/node",
                selectors=[
                    Selector(type="unix", value="uid:1001"),
                    Selector(type="unix", value="sha256:abc"),
                ],
            )
        )
        results = registration_store.find_by_selectors(
            [
                Selector(type="unix", value="uid:1001"),
                Selector(type="unix", value="sha256:abc"),
                Selector(type="unix", value="gid:100"),
            ]
        )
        assert len(results) == 1
