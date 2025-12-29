"""
Tests for Credential Management

This module tests:
- Credential format validation
- OAuth override behavior
- Token refresh capability
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone

from google.oauth2.credentials import Credentials

from auth.credential_store import (
    LocalDirectoryCredentialStore,
)
from auth.oauth_config import (
    reload_oauth_config,
    is_oauth_override_credentials_json,
)


class TestCredentialFormat:
    """Tests for credential format handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = LocalDirectoryCredentialStore(base_dir=self.temp_dir)
        self.test_email = "test@example.com"

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_save_credentials_creates_complete_structure(self):
        """Test that store_raw_tokens creates a complete credential structure."""
        tokens = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar",
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client_id",
            client_secret="test_client_secret",
        )

        assert result is True

        # Verify the stored credential has all required fields
        credentials = self.store.get_credential(self.test_email)
        assert credentials is not None
        assert credentials.token == "test_access_token"
        assert credentials.refresh_token == "test_refresh_token"
        assert credentials.client_id == "test_client_id"
        assert credentials.client_secret == "test_client_secret"
        assert credentials.token_uri == "https://oauth2.googleapis.com/token"
        assert credentials.scopes is not None
        assert len(credentials.scopes) == 2
        assert credentials.expiry is not None

    def test_save_credentials_handles_both_token_field_names(self):
        """Test that both 'access_token' and 'token' field names work."""
        # Test with 'access_token'
        tokens_with_access_token = {
            "access_token": "access_token_value",
            "refresh_token": "refresh_token_value",
        }

        result1 = self.store.store_raw_tokens(
            user_email="user1@example.com",
            tokens=tokens_with_access_token,
            client_id="test_client",
            client_secret="test_secret",
        )
        assert result1 is True
        creds1 = self.store.get_credential("user1@example.com")
        assert creds1.token == "access_token_value"

        # Test with 'token'
        tokens_with_token = {
            "token": "token_value",
            "refresh_token": "refresh_token_value",
        }

        result2 = self.store.store_raw_tokens(
            user_email="user2@example.com",
            tokens=tokens_with_token,
            client_id="test_client",
            client_secret="test_secret",
        )
        assert result2 is True
        creds2 = self.store.get_credential("user2@example.com")
        assert creds2.token == "token_value"

        # Test that 'access_token' takes priority when both are present
        tokens_with_both = {
            "access_token": "primary_token",
            "token": "secondary_token",
            "refresh_token": "refresh_token_value",
        }

        result3 = self.store.store_raw_tokens(
            user_email="user3@example.com",
            tokens=tokens_with_both,
            client_id="test_client",
            client_secret="test_secret",
        )
        assert result3 is True
        creds3 = self.store.get_credential("user3@example.com")
        assert creds3.token == "primary_token"

    def test_save_credentials_fails_without_token(self):
        """Test that store_raw_tokens returns False when no token is provided."""
        tokens = {
            "refresh_token": "refresh_token_value",
            "expires_in": 3600,
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )
        assert result is False

    def test_save_credentials_fails_with_empty_token(self):
        """Test that store_raw_tokens returns False when token is empty string."""
        tokens = {
            "access_token": "",
            "token": "",
            "refresh_token": "refresh_token_value",
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )
        assert result is False

    def test_save_credentials_calculates_expiry_from_expires_in(self):
        """Test that expiry is calculated from expires_in when not provided."""
        expires_in_seconds = 3600  # 1 hour
        tokens = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
            "expires_in": expires_in_seconds,
        }

        before_save = datetime.now(timezone.utc)
        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )
        after_save = datetime.now(timezone.utc)

        assert result is True
        credentials = self.store.get_credential(self.test_email)
        assert credentials.expiry is not None

        # The expiry should be approximately now + expires_in
        # Since Google auth library uses timezone-naive datetime, we compare without timezone
        expected_min = before_save + timedelta(seconds=expires_in_seconds)
        expected_max = after_save + timedelta(seconds=expires_in_seconds)

        # Compare as naive datetimes
        expiry_naive = credentials.expiry
        expected_min_naive = expected_min.replace(tzinfo=None)
        expected_max_naive = expected_max.replace(tzinfo=None)

        assert expected_min_naive <= expiry_naive <= expected_max_naive

    def test_save_credentials_uses_explicit_expiry_when_provided(self):
        """Test that explicit expiry takes priority over expires_in."""
        # Use a date 1 year in the future for testing
        future_date = datetime.now(timezone.utc) + timedelta(days=365)
        explicit_expiry = future_date.isoformat()
        tokens = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
            "expiry": explicit_expiry,
            "expires_in": 3600,  # Should be ignored
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )

        assert result is True
        credentials = self.store.get_credential(self.test_email)
        assert credentials.expiry is not None
        # The stored expiry should match the future date (timezone-naive)
        assert credentials.expiry.year == future_date.year
        assert credentials.expiry.month == future_date.month
        assert credentials.expiry.day == future_date.day

    def test_save_credentials_parses_scope_string_to_list(self):
        """Test that space-separated scope strings are parsed into lists."""
        scope_string = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive"
        tokens = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
            "scope": scope_string,
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )

        assert result is True
        credentials = self.store.get_credential(self.test_email)
        assert credentials.scopes is not None
        assert isinstance(credentials.scopes, list)
        assert len(credentials.scopes) == 3
        assert "https://www.googleapis.com/auth/gmail.readonly" in credentials.scopes
        assert "https://www.googleapis.com/auth/calendar" in credentials.scopes
        assert "https://www.googleapis.com/auth/drive" in credentials.scopes

    def test_save_credentials_handles_scopes_as_list(self):
        """Test that scopes provided as list are preserved."""
        scopes_list = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/calendar",
        ]
        tokens = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
            "scopes": scopes_list,
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )

        assert result is True
        credentials = self.store.get_credential(self.test_email)
        assert credentials.scopes == scopes_list


class TestOAuthOverrideBehavior:
    """Tests for OAuth override configuration behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        # Clear any cached OAuth config
        import auth.oauth_config

        auth.oauth_config._oauth_config = None

    def teardown_method(self):
        """Clean up environment variables."""
        if "IS_OAUTH_OVERRIDE_CREDENTIALS_JSON" in os.environ:
            del os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"]
        # Reset the config
        import auth.oauth_config

        auth.oauth_config._oauth_config = None

    def test_oauth_override_true_by_default(self):
        """Test that IS_OAUTH_OVERRIDE_CREDENTIALS_JSON defaults to true."""
        # Ensure environment variable is not set
        if "IS_OAUTH_OVERRIDE_CREDENTIALS_JSON" in os.environ:
            del os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"]

        config = reload_oauth_config()
        assert config.is_oauth_override_credentials_json is True
        assert is_oauth_override_credentials_json() is True

    def test_oauth_override_true_skips_mcp_credentials_json(self):
        """Test that when override is true, OAuth credentials take priority."""
        os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"] = "true"
        config = reload_oauth_config()

        assert config.is_oauth_override_credentials_json is True
        # When true, OAuth credentials from interactive flow should take priority
        # over MCP_CREDENTIALS_JSON environment variable

    def test_oauth_override_false_allows_mcp_credentials_json(self):
        """Test that when override is false, MCP_CREDENTIALS_JSON can overwrite."""
        os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"] = "false"
        config = reload_oauth_config()

        assert config.is_oauth_override_credentials_json is False
        # When false, MCP_CREDENTIALS_JSON environment variable can
        # overwrite existing OAuth credentials

    def test_oauth_override_case_insensitive(self):
        """Test that the override setting is case insensitive."""
        test_cases = [
            ("TRUE", True),
            ("True", True),
            ("true", True),
            ("FALSE", False),
            ("False", False),
            ("false", False),
        ]

        for value, expected in test_cases:
            os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"] = value
            config = reload_oauth_config()
            assert config.is_oauth_override_credentials_json is expected, (
                f"Failed for value: {value}"
            )

    def test_no_existing_credentials_always_uses_mcp_credentials_json(self):
        """Test that MCP_CREDENTIALS_JSON is used when no existing credentials."""
        # This is a behavioral test - when no OAuth credentials exist,
        # MCP_CREDENTIALS_JSON should be used regardless of override setting
        temp_dir = tempfile.mkdtemp()
        try:
            store = LocalDirectoryCredentialStore(base_dir=temp_dir)

            # Verify no credentials exist
            credentials = store.get_credential("nonexistent@example.com")
            assert credentials is None

            # In this case, MCP_CREDENTIALS_JSON would be used to provision
            # credentials if available
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_environment_summary_includes_override_setting(self):
        """Test that get_environment_summary includes the override setting."""
        os.environ["IS_OAUTH_OVERRIDE_CREDENTIALS_JSON"] = "false"
        config = reload_oauth_config()

        summary = config.get_environment_summary()
        assert "is_oauth_override_credentials_json" in summary
        assert summary["is_oauth_override_credentials_json"] is False


class TestCredentialRefreshCapability:
    """Tests for credential refresh capability."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.store = LocalDirectoryCredentialStore(base_dir=self.temp_dir)
        self.test_email = "test@example.com"

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_saved_credentials_have_refresh_requirements(self):
        """Test that saved credentials include all fields required for refresh."""
        tokens = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client_id",
            client_secret="test_client_secret",
        )

        assert result is True

        credentials = self.store.get_credential(self.test_email)

        # All fields required for token refresh
        assert credentials.token is not None, "token is required"
        assert credentials.refresh_token is not None, "refresh_token is required"
        assert credentials.token_uri is not None, "token_uri is required"
        assert credentials.client_id is not None, "client_id is required"
        assert credentials.client_secret is not None, "client_secret is required"
        assert credentials.scopes is not None, "scopes is required"
        assert credentials.expiry is not None, "expiry is required"

    def test_credentials_can_be_loaded_by_google_auth_library(self):
        """Test that stored credentials are compatible with google-auth library."""
        tokens = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
            "token_uri": "https://oauth2.googleapis.com/token",
        }

        self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client_id",
            client_secret="test_client_secret",
        )

        # Load credentials and verify it's a valid Credentials object
        credentials = self.store.get_credential(self.test_email)

        assert isinstance(credentials, Credentials)

        # Verify it has all expected attributes
        assert hasattr(credentials, "token")
        assert hasattr(credentials, "refresh_token")
        assert hasattr(credentials, "token_uri")
        assert hasattr(credentials, "client_id")
        assert hasattr(credentials, "client_secret")
        assert hasattr(credentials, "scopes")
        assert hasattr(credentials, "expiry")
        assert hasattr(credentials, "expired")
        assert hasattr(credentials, "valid")

    def test_credential_store_round_trip(self):
        """Test that credentials survive a store/load round trip."""
        original_credentials = Credentials(
            token="original_token",
            refresh_token="original_refresh_token",
            token_uri="https://oauth2.googleapis.com/token",
            client_id="original_client_id",
            client_secret="original_client_secret",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            expiry=datetime(2025, 12, 31, 23, 59, 59),
        )

        # Store the credentials
        result = self.store.store_credential(self.test_email, original_credentials)
        assert result is True

        # Load them back
        loaded_credentials = self.store.get_credential(self.test_email)

        # Verify all fields match
        assert loaded_credentials.token == original_credentials.token
        assert loaded_credentials.refresh_token == original_credentials.refresh_token
        assert loaded_credentials.token_uri == original_credentials.token_uri
        assert loaded_credentials.client_id == original_credentials.client_id
        assert loaded_credentials.client_secret == original_credentials.client_secret
        assert loaded_credentials.scopes == original_credentials.scopes
        assert loaded_credentials.expiry == original_credentials.expiry

    def test_store_raw_tokens_with_custom_token_uri(self):
        """Test that custom token_uri is preserved."""
        custom_token_uri = "https://custom.example.com/token"
        tokens = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
            "token_uri": custom_token_uri,
        }

        result = self.store.store_raw_tokens(
            user_email=self.test_email,
            tokens=tokens,
            client_id="test_client",
            client_secret="test_secret",
        )

        assert result is True
        credentials = self.store.get_credential(self.test_email)
        assert credentials.token_uri == custom_token_uri
