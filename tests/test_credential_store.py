"""
Tests for the Credential Store API.

These tests verify the functionality of the credential storage system,
including:
- LocalDirectoryCredentialStore operations
- Credential serialization/deserialization
- Timezone-aware expiry handling
- User listing functionality
"""

import json
import os
import tempfile
from datetime import datetime, timezone


class TestLocalDirectoryCredentialStore:
    """Tests for LocalDirectoryCredentialStore."""

    def test_init_with_env_var(self):
        """Test initialization with GOOGLE_MCP_CREDENTIALS_DIR environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["GOOGLE_MCP_CREDENTIALS_DIR"] = tmpdir
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore()
            assert store.base_dir == tmpdir

    def test_init_with_custom_dir(self):
        """Test initialization with custom base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            assert store.base_dir == tmpdir

    def test_store_and_get_credential(self, mock_credentials):
        """Test storing and retrieving credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)

            # Store credentials
            result = store.store_credential("test@example.com", mock_credentials)
            assert result is True

            # Verify file was created
            creds_path = os.path.join(tmpdir, "test@example.com.json")
            assert os.path.exists(creds_path)

            # Retrieve credentials
            loaded_creds = store.get_credential("test@example.com")
            assert loaded_creds is not None
            assert loaded_creds.token == mock_credentials.token
            assert loaded_creds.refresh_token == mock_credentials.refresh_token

    def test_get_credential_nonexistent(self):
        """Test getting credentials that don't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            result = store.get_credential("nonexistent@example.com")
            assert result is None

    def test_delete_credential(self, mock_credentials):
        """Test deleting credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)

            # Store then delete
            store.store_credential("test@example.com", mock_credentials)
            result = store.delete_credential("test@example.com")
            assert result is True

            # Verify file was deleted
            creds_path = os.path.join(tmpdir, "test@example.com.json")
            assert not os.path.exists(creds_path)

    def test_delete_nonexistent_credential(self):
        """Test deleting credentials that don't exist returns True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            result = store.delete_credential("nonexistent@example.com")
            assert result is True

    def test_list_users(self, mock_credentials):
        """Test listing users with stored credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)

            # Store multiple credentials
            store.store_credential("user1@example.com", mock_credentials)
            store.store_credential("user2@example.com", mock_credentials)

            users = store.list_users()
            assert len(users) == 2
            assert "user1@example.com" in users
            assert "user2@example.com" in users

    def test_list_users_empty(self):
        """Test listing users when no credentials exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            users = store.list_users()
            assert users == []

    def test_timezone_aware_expiry_handling(self):
        """Test that timezone-aware expiry times are properly converted to naive datetimes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.credential_store import LocalDirectoryCredentialStore

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)

            # Create a credential file with timezone-aware expiry
            expiry_with_tz = datetime(2025, 12, 31, 12, 0, 0, tzinfo=timezone.utc)
            creds_data = {
                "token": "test_token",
                "refresh_token": "test_refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "expiry": expiry_with_tz.isoformat(),
            }

            creds_path = os.path.join(tmpdir, "test@example.com.json")
            with open(creds_path, "w") as f:
                json.dump(creds_data, f)

            # Load and verify expiry is timezone-naive
            loaded_creds = store.get_credential("test@example.com")
            assert loaded_creds is not None
            assert loaded_creds.expiry is not None
            assert loaded_creds.expiry.tzinfo is None


class TestCredentialStoreGlobalInstance:
    """Tests for the global credential store singleton."""

    def test_get_credential_store_singleton(self):
        """Test that get_credential_store returns a singleton instance."""
        from auth.credential_store import get_credential_store

        # Reset to None first
        import auth.credential_store

        auth.credential_store._credential_store = None

        store1 = get_credential_store()
        store2 = get_credential_store()
        assert store1 is store2

    def test_set_credential_store(self):
        """Test setting a custom credential store."""
        from auth.credential_store import (
            get_credential_store,
            set_credential_store,
            LocalDirectoryCredentialStore,
        )
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            set_credential_store(custom_store)

            assert get_credential_store() is custom_store
