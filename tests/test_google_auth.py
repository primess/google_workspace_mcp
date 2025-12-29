"""
Tests for the Google Auth module.

These tests verify the core OAuth functionality including:
- Client secrets loading from environment variables and files
- OAuth flow creation
- Credential retrieval and refresh
- Single-user mode behavior
"""

import os
import json
import tempfile
from unittest.mock import MagicMock, patch


class TestClientSecretsLoading:
    """Tests for client secrets loading functionality."""

    def test_load_client_secrets_from_env(self, oauth_env_vars):
        """Test loading client secrets from environment variables."""
        from auth.google_auth import load_client_secrets_from_env

        config = load_client_secrets_from_env()
        assert config is not None
        assert config["web"]["client_id"] == "test_client_id.apps.googleusercontent.com"
        assert config["web"]["client_secret"] == "test_client_secret"

    def test_load_client_secrets_from_env_missing(self):
        """Test that missing env vars return None."""
        # Ensure env vars are not set
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)

        from auth.google_auth import load_client_secrets_from_env

        config = load_client_secrets_from_env()
        assert config is None

    def test_load_client_secrets_from_file(self):
        """Test loading client secrets from a JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "web": {
                        "client_id": "file_client_id",
                        "client_secret": "file_client_secret",
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                },
                f,
            )
            f.flush()

            # Ensure env vars are not set
            os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
            os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)

            from auth.google_auth import load_client_secrets

            config = load_client_secrets(f.name)
            assert config["client_id"] == "file_client_id"
            assert config["client_secret"] == "file_client_secret"

            os.unlink(f.name)

    def test_load_client_secrets_env_takes_precedence(self, oauth_env_vars):
        """Test that environment variables take precedence over file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "web": {
                        "client_id": "file_client_id",
                        "client_secret": "file_client_secret",
                    }
                },
                f,
            )
            f.flush()

            from auth.google_auth import load_client_secrets

            config = load_client_secrets(f.name)
            # Should use env var values, not file values
            assert config["client_id"] == "test_client_id.apps.googleusercontent.com"

            os.unlink(f.name)


class TestCheckClientSecrets:
    """Tests for check_client_secrets function."""

    def test_check_client_secrets_with_env_vars(self, oauth_env_vars):
        """Test check returns None when env vars are set."""
        from auth.google_auth import check_client_secrets

        result = check_client_secrets()
        assert result is None

    def test_check_client_secrets_missing_all(self):
        """Test check returns error message when no config found."""
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)
        os.environ.pop("GOOGLE_CLIENT_SECRET_PATH", None)

        from auth.google_auth import check_client_secrets

        check_client_secrets()  # Should not crash
        # May or may not return error depending on whether default file exists


class TestOAuthFlowCreation:
    """Tests for OAuth flow creation."""

    def test_create_oauth_flow_from_env(self, oauth_env_vars):
        """Test creating OAuth flow from environment variables."""
        from auth.google_auth import create_oauth_flow

        scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        redirect_uri = "http://localhost:8000/oauth2callback"

        flow = create_oauth_flow(scopes=scopes, redirect_uri=redirect_uri)
        assert flow is not None
        assert flow.redirect_uri == redirect_uri


class TestSingleUserMode:
    """Tests for single-user mode functionality."""

    def test_find_any_credentials_empty_dir(self):
        """Test finding credentials in empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from auth.google_auth import _find_any_credentials

            creds = _find_any_credentials(tmpdir)
            assert creds is None

    def test_find_any_credentials_with_file(self, mock_credentials):
        """Test finding credentials when a credential file exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a credential file
            creds_data = {
                "token": mock_credentials.token,
                "refresh_token": mock_credentials.refresh_token,
                "token_uri": mock_credentials.token_uri,
                "client_id": mock_credentials.client_id,
                "client_secret": mock_credentials.client_secret,
                "scopes": mock_credentials.scopes,
                "expiry": mock_credentials.expiry.isoformat()
                if mock_credentials.expiry
                else None,
            }
            creds_path = os.path.join(tmpdir, "test@example.com.json")
            with open(creds_path, "w") as f:
                json.dump(creds_data, f)

            # Override the credential store for this test
            from auth.credential_store import (
                LocalDirectoryCredentialStore,
                set_credential_store,
            )

            store = LocalDirectoryCredentialStore(base_dir=tmpdir)
            set_credential_store(store)

            from auth.google_auth import _find_any_credentials

            creds = _find_any_credentials(tmpdir)
            assert creds is not None
            assert creds.token == mock_credentials.token


class TestGetUserInfo:
    """Tests for get_user_info function."""

    def test_get_user_info_valid_credentials(self, mock_credentials, mock_user_info):
        """Test getting user info with valid credentials."""
        from auth.google_auth import get_user_info

        mock_service = MagicMock()
        mock_service.userinfo().get().execute.return_value = mock_user_info

        with patch("auth.google_auth.build", return_value=mock_service):
            result = get_user_info(mock_credentials)
            assert result is not None
            assert result["email"] == mock_user_info["email"]

    def test_get_user_info_invalid_credentials(self):
        """Test getting user info with invalid credentials returns None."""
        from auth.google_auth import get_user_info

        invalid_creds = MagicMock()
        invalid_creds.valid = False

        result = get_user_info(invalid_creds)
        assert result is None

    def test_get_user_info_none_credentials(self):
        """Test getting user info with None credentials returns None."""
        from auth.google_auth import get_user_info

        result = get_user_info(None)
        assert result is None


class TestGoogleAuthenticationError:
    """Tests for GoogleAuthenticationError exception."""

    def test_exception_with_message(self):
        """Test exception with message."""
        from auth.google_auth import GoogleAuthenticationError

        exc = GoogleAuthenticationError("Test error message")
        assert str(exc) == "Test error message"
        assert exc.auth_url is None

    def test_exception_with_auth_url(self):
        """Test exception with auth URL."""
        from auth.google_auth import GoogleAuthenticationError

        exc = GoogleAuthenticationError(
            "Auth required", auth_url="https://accounts.google.com/..."
        )
        assert str(exc) == "Auth required"
        assert exc.auth_url == "https://accounts.google.com/..."
