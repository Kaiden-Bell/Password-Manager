"""
test_vault.py — Tests for the vault module.

Run with:
    python -m pytest tests/test_vault.py -v
"""

import pytest


class TestVaultCreation:
    """Tests for create_empty_vault()."""

    def test_empty_vault_structure(self):
        """Should return {"entries": []}."""
        pytest.skip("Not implemented")


class TestCredentialCRUD:
    """Tests for add/update/delete/search credentials."""

    def test_add_credential(self):
        """Should add an entry and re-encrypt."""
        pytest.skip("Not implemented")

    def test_add_assigns_entry_id(self):
        """Should assign incrementing entry_id."""
        pytest.skip("Not implemented")

    def test_update_credential(self):
        """Should update specified fields."""
        pytest.skip("Not implemented")

    def test_update_nonexistent_fails(self):
        """Should raise ValueError for unknown entry_id."""
        pytest.skip("Not implemented")

    def test_delete_credential(self):
        """Should remove the entry and re-encrypt."""
        pytest.skip("Not implemented")

    def test_delete_nonexistent_fails(self):
        """Should raise ValueError for unknown entry_id."""
        pytest.skip("Not implemented")

    def test_search_by_site(self):
        """Should find entries matching site query."""
        pytest.skip("Not implemented")

    def test_search_by_username(self):
        """Should find entries matching username query."""
        pytest.skip("Not implemented")

    def test_search_case_insensitive(self):
        """Search should be case-insensitive."""
        pytest.skip("Not implemented")

    def test_search_no_results(self):
        """Should return empty list for no matches."""
        pytest.skip("Not implemented")
