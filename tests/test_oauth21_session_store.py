"""
Tests for the OAuth21SessionStore.

These tests verify the functionality of the OAuth 2.1 session store
which manages user sessions, credentials, and OAuth state validation.
"""

import pytest
from unittest.mock import MagicMock


class TestOAuth21SessionStore:
    """Tests for OAuth21SessionStore functionality."""

    def test_store_and_get_session(self, mock_credentials):
        """Test storing and retrieving a session."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        # Store session
        store.store_session(
            user_email="test@example.com",
            access_token=mock_credentials.token,
            refresh_token=mock_credentials.refresh_token,
            token_uri=mock_credentials.token_uri,
            client_id=mock_credentials.client_id,
            client_secret=mock_credentials.client_secret,
            scopes=mock_credentials.scopes,
            expiry=mock_credentials.expiry,
            mcp_session_id="mcp_session_123",
        )

        # Get credentials by MCP session
        creds = store.get_credentials_by_mcp_session("mcp_session_123")
        assert creds is not None
        assert creds.token == mock_credentials.token

    def test_get_user_by_mcp_session(self, mock_credentials):
        """Test getting user email by MCP session ID."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        store.store_session(
            user_email="test@example.com",
            access_token=mock_credentials.token,
            refresh_token=mock_credentials.refresh_token,
            token_uri=mock_credentials.token_uri,
            client_id=mock_credentials.client_id,
            client_secret=mock_credentials.client_secret,
            scopes=mock_credentials.scopes,
            expiry=mock_credentials.expiry,
            mcp_session_id="mcp_session_123",
        )

        user = store.get_user_by_mcp_session("mcp_session_123")
        assert user == "test@example.com"

    def test_get_nonexistent_session(self):
        """Test getting credentials for a non-existent session."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()
        creds = store.get_credentials_by_mcp_session("nonexistent_session")
        assert creds is None

    def test_oauth_state_store_and_validate(self):
        """Test storing and validating OAuth state."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        # Store state
        store.store_oauth_state("test_state_123", session_id="session_456")

        # Validate and consume state
        result = store.validate_and_consume_oauth_state(
            "test_state_123", session_id="session_456"
        )
        assert result is not None
        assert result.get("session_id") == "session_456"

    def test_oauth_state_consumed_cannot_reuse(self):
        """Test that consumed OAuth state cannot be reused."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        # Store and consume state
        store.store_oauth_state("test_state_123")
        store.validate_and_consume_oauth_state("test_state_123")

        # Try to validate again - should fail
        with pytest.raises(ValueError):
            store.validate_and_consume_oauth_state("test_state_123")

    def test_oauth_state_missing_raises_error(self):
        """Test that validating missing state raises ValueError."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        with pytest.raises(ValueError):
            store.validate_and_consume_oauth_state("nonexistent_state")

    def test_get_credentials_with_validation_same_user(self, mock_credentials):
        """Test getting credentials with validation for the same user."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        store.store_session(
            user_email="test@example.com",
            access_token=mock_credentials.token,
            refresh_token=mock_credentials.refresh_token,
            token_uri=mock_credentials.token_uri,
            client_id=mock_credentials.client_id,
            client_secret=mock_credentials.client_secret,
            scopes=mock_credentials.scopes,
            expiry=mock_credentials.expiry,
            mcp_session_id="mcp_session_123",
        )

        # Should succeed when auth_token_email matches stored user
        creds = store.get_credentials_with_validation(
            requested_user_email="test@example.com",
            session_id="mcp_session_123",
            auth_token_email="test@example.com",
        )
        assert creds is not None

    def test_get_credentials_with_validation_different_user(self, mock_credentials):
        """Test getting credentials with validation for a different user returns None."""
        from auth.oauth21_session_store import OAuth21SessionStore

        store = OAuth21SessionStore()

        store.store_session(
            user_email="user1@example.com",
            access_token=mock_credentials.token,
            refresh_token=mock_credentials.refresh_token,
            token_uri=mock_credentials.token_uri,
            client_id=mock_credentials.client_id,
            client_secret=mock_credentials.client_secret,
            scopes=mock_credentials.scopes,
            expiry=mock_credentials.expiry,
            mcp_session_id="mcp_session_123",
        )

        # Should return None when auth_token_email doesn't match
        creds = store.get_credentials_with_validation(
            requested_user_email="user2@example.com",
            session_id="mcp_session_123",
            auth_token_email="user1@example.com",
        )
        assert creds is None


class TestGlobalSessionStore:
    """Tests for global session store singleton."""

    def test_get_oauth21_session_store_singleton(self):
        """Test that get_oauth21_session_store returns a singleton."""
        # Reset singleton first
        import auth.oauth21_session_store

        auth.oauth21_session_store._session_store = None

        from auth.oauth21_session_store import get_oauth21_session_store

        store1 = get_oauth21_session_store()
        store2 = get_oauth21_session_store()
        assert store1 is store2

    def test_set_and_get_auth_provider(self):
        """Test setting and getting the auth provider."""
        from auth.oauth21_session_store import set_auth_provider, get_auth_provider

        mock_provider = MagicMock()
        set_auth_provider(mock_provider)
        assert get_auth_provider() is mock_provider

        # Reset to None
        set_auth_provider(None)
        assert get_auth_provider() is None
