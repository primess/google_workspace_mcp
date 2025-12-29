"""
Tests for the External OAuth Provider.

These tests verify the functionality of the ExternalOAuthProvider class
which extends FastMCP's GoogleProvider to support external OAuth flows
where access tokens (ya29.*) are issued by external systems.
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

# Add the project root to the Python path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


class TestExternalOAuthProvider:
    """Tests for ExternalOAuthProvider functionality."""

    def test_init_stores_credentials(self):
        """Test that initialization stores client credentials."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )
            assert provider._client_id == "test_client_id"
            assert provider._client_secret == "test_client_secret"

    @pytest.mark.asyncio
    async def test_verify_token_ya29_valid(self, mock_user_info):
        """Test verifying a valid ya29.* access token."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )
            provider.required_scopes = [
                "https://www.googleapis.com/auth/gmail.readonly"
            ]

            # Mock the get_user_info function at the import location
            with patch("auth.google_auth.get_user_info") as mock_get_user_info:
                mock_get_user_info.return_value = mock_user_info

                result = await provider.verify_token("ya29.test_access_token")

                assert result is not None
                assert result.email == mock_user_info["email"]
                assert result.claims["email"] == mock_user_info["email"]

    @pytest.mark.asyncio
    async def test_verify_token_ya29_invalid(self):
        """Test verifying an invalid ya29.* access token returns None."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )

            # Mock the get_user_info function to return None (invalid token)
            with patch("auth.google_auth.get_user_info") as mock_get_user_info:
                mock_get_user_info.return_value = None

                result = await provider.verify_token("ya29.invalid_token")

                assert result is None

    @pytest.mark.asyncio
    async def test_verify_token_ya29_exception(self):
        """Test verifying a ya29.* token that causes an exception."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )

            # Mock the get_user_info function to raise an exception
            with patch("auth.google_auth.get_user_info") as mock_get_user_info:
                mock_get_user_info.side_effect = Exception("API Error")

                result = await provider.verify_token("ya29.error_token")

                assert result is None

    @pytest.mark.asyncio
    async def test_verify_token_jwt_delegates_to_parent(self):
        """Test that JWT tokens delegate to parent class implementation."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )

            # Mock parent's verify_token
            mock_access_token = MagicMock()
            mock_access_token.email = "jwt_user@example.com"

            with patch.object(
                external_oauth_provider.GoogleProvider,
                "verify_token",
                new_callable=AsyncMock,
            ) as mock_parent_verify:
                mock_parent_verify.return_value = mock_access_token

                # JWT tokens don't start with ya29.
                result = await provider.verify_token("eyJhbGciOiJSUzI1NiIsInR...")

                mock_parent_verify.assert_called_once_with("eyJhbGciOiJSUzI1NiIsInR...")
                assert result == mock_access_token

    @pytest.mark.asyncio
    async def test_verify_token_ya29_no_email(self):
        """Test verifying a ya29.* token where userinfo has no email."""
        from auth import external_oauth_provider

        with patch.object(
            external_oauth_provider.GoogleProvider, "__init__", return_value=None
        ):
            provider = external_oauth_provider.ExternalOAuthProvider(
                client_id="test_client_id", client_secret="test_client_secret"
            )

            # Mock get_user_info to return info without email
            with patch("auth.google_auth.get_user_info") as mock_get_user_info:
                mock_get_user_info.return_value = {"id": "123", "name": "Test User"}

                result = await provider.verify_token("ya29.no_email_token")

                assert result is None
