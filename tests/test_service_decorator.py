"""
Tests for the Service Decorator.

These tests verify the functionality of the @require_google_service
decorator which handles automatic Google service authentication.
"""

import inspect
import pytest
from unittest.mock import MagicMock, patch


class TestScopeResolution:
    """Tests for scope resolution functionality."""

    def test_resolve_single_scope_name(self):
        """Test resolving a single scope name to URL."""
        from auth.service_decorator import _resolve_scopes, SCOPE_GROUPS

        result = _resolve_scopes("gmail_read")
        assert result == [SCOPE_GROUPS["gmail_read"]]

    def test_resolve_multiple_scope_names(self):
        """Test resolving multiple scope names to URLs."""
        from auth.service_decorator import _resolve_scopes, SCOPE_GROUPS

        result = _resolve_scopes(["gmail_read", "drive_read"])
        assert SCOPE_GROUPS["gmail_read"] in result
        assert SCOPE_GROUPS["drive_read"] in result

    def test_resolve_scope_url_passthrough(self):
        """Test that scope URLs pass through unchanged."""
        from auth.service_decorator import _resolve_scopes

        url = "https://www.googleapis.com/auth/custom.scope"
        result = _resolve_scopes(url)
        assert result == [url]

    def test_resolve_mixed_scopes(self):
        """Test resolving a mix of scope names and URLs."""
        from auth.service_decorator import _resolve_scopes

        custom_url = "https://www.googleapis.com/auth/custom.scope"
        result = _resolve_scopes(["gmail_read", custom_url])
        assert len(result) == 2
        assert custom_url in result


class TestServiceConfigs:
    """Tests for service configuration mapping."""

    def test_all_services_have_config(self):
        """Test that all expected services have configuration."""
        from auth.service_decorator import SERVICE_CONFIGS

        expected_services = [
            "gmail",
            "drive",
            "calendar",
            "docs",
            "sheets",
            "chat",
            "forms",
            "slides",
            "tasks",
            "customsearch",
        ]
        for service in expected_services:
            assert service in SERVICE_CONFIGS
            assert "service" in SERVICE_CONFIGS[service]
            assert "version" in SERVICE_CONFIGS[service]


class TestScopeGroups:
    """Tests for scope group definitions."""

    def test_gmail_scopes_exist(self):
        """Test Gmail scopes are defined."""
        from auth.service_decorator import SCOPE_GROUPS

        assert "gmail_read" in SCOPE_GROUPS
        assert "gmail_send" in SCOPE_GROUPS
        assert "gmail_modify" in SCOPE_GROUPS

    def test_drive_scopes_exist(self):
        """Test Drive scopes are defined."""
        from auth.service_decorator import SCOPE_GROUPS

        assert "drive_read" in SCOPE_GROUPS
        assert "drive_file" in SCOPE_GROUPS

    def test_calendar_scopes_exist(self):
        """Test Calendar scopes are defined."""
        from auth.service_decorator import SCOPE_GROUPS

        assert "calendar_read" in SCOPE_GROUPS
        assert "calendar_events" in SCOPE_GROUPS


class TestTokenRefreshErrorHandling:
    """Tests for token refresh error handling."""

    def test_handle_invalid_grant_error(self):
        """Test handling of invalid_grant refresh error."""
        from auth.service_decorator import _handle_token_refresh_error
        from google.auth.exceptions import RefreshError

        error = RefreshError("Token has been expired or revoked.")
        result = _handle_token_refresh_error(error, "test@example.com", "gmail")

        assert "Authentication Required" in result
        assert "test@example.com" in result
        # Check for presence of the core message
        assert "expired" in result.lower() or "revoked" in result.lower()

    def test_handle_other_refresh_error(self):
        """Test handling of other refresh errors."""
        from auth.service_decorator import _handle_token_refresh_error
        from google.auth.exceptions import RefreshError

        error = RefreshError("Network error occurred")
        result = _handle_token_refresh_error(error, "test@example.com", "gmail")

        assert "test@example.com" in result


class TestAuthContextExtraction:
    """Tests for authentication context extraction."""

    def test_get_auth_context_no_context(self):
        """Test getting auth context when no FastMCP context is available."""
        from auth.service_decorator import _get_auth_context

        with patch("auth.service_decorator.get_context", return_value=None):
            user, method, session = _get_auth_context("test_tool")
            assert user is None
            assert method is None
            assert session is None

    def test_get_auth_context_with_context(self):
        """Test getting auth context when FastMCP context is available."""
        from auth.service_decorator import _get_auth_context

        mock_ctx = MagicMock()
        mock_ctx.get_state.side_effect = lambda key: {
            "authenticated_user_email": "user@example.com",
            "authenticated_via": "oauth21",
        }.get(key)
        mock_ctx.session_id = "session_123"

        with patch("auth.service_decorator.get_context", return_value=mock_ctx):
            user, method, session = _get_auth_context("test_tool")
            assert user == "user@example.com"
            assert method == "oauth21"
            assert session == "session_123"


class TestDocstringModification:
    """Tests for docstring modification in OAuth 2.1 mode."""

    def test_remove_user_email_from_docstring(self):
        """Test removing user_google_email from docstring."""
        from auth.service_decorator import _remove_user_email_arg_from_docstring

        docstring = """
        Search for emails.

        Args:
            user_google_email (str): The user's Google email address. Required.
            query (str): Search query.

        Returns:
            List of emails.
        """

        result = _remove_user_email_arg_from_docstring(docstring)
        assert "user_google_email" not in result
        assert "query (str)" in result

    def test_remove_user_email_preserves_other_args(self):
        """Test that other args are preserved."""
        from auth.service_decorator import _remove_user_email_arg_from_docstring

        docstring = """
        Args:
            user_google_email (str): The user's Google email address. Required.
            other_param (str): Another parameter.
        """

        result = _remove_user_email_arg_from_docstring(docstring)
        assert "other_param (str)" in result

    def test_remove_user_email_empty_docstring(self):
        """Test handling of empty/None docstring."""
        from auth.service_decorator import _remove_user_email_arg_from_docstring

        assert _remove_user_email_arg_from_docstring(None) is None
        assert _remove_user_email_arg_from_docstring("") == ""


class TestRequireGoogleServiceDecorator:
    """Tests for @require_google_service decorator."""

    def test_decorator_requires_service_param(self):
        """Test that decorated function must have 'service' as first parameter."""
        from auth.service_decorator import require_google_service

        # This should raise TypeError because func has no 'service' param
        with pytest.raises(TypeError) as exc_info:

            @require_google_service("gmail", "gmail_read")
            async def invalid_func(other_param: str):
                pass

        assert "service" in str(exc_info.value)

    def test_decorator_removes_service_from_signature(self):
        """Test that 'service' is removed from wrapper signature."""
        from auth.service_decorator import require_google_service

        with patch("auth.service_decorator.is_oauth21_enabled", return_value=False):

            @require_google_service("gmail", "gmail_read")
            async def test_func(
                service, user_google_email: str, query: str = "test"
            ) -> list:
                """Test function."""
                return []

            sig = inspect.signature(test_func)
            param_names = list(sig.parameters.keys())
            assert "service" not in param_names
            assert "user_google_email" in param_names
            assert "query" in param_names
