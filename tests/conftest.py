"""
Pytest configuration and shared fixtures for Google Workspace MCP tests.
"""

import os
import sys
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta, timezone

# Add the project root to the Python path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test."""
    # Store original values
    original_env = os.environ.copy()

    yield

    # Restore original values
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_credentials():
    """Create mock Google OAuth credentials."""
    creds = MagicMock()
    creds.token = "ya29.test_access_token"
    creds.refresh_token = "test_refresh_token"
    creds.token_uri = "https://oauth2.googleapis.com/token"
    creds.client_id = "test_client_id.apps.googleusercontent.com"
    creds.client_secret = "test_client_secret"
    creds.scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
    ]
    # Use timezone-aware datetime and convert to naive for Google auth compatibility
    creds.expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    creds.valid = True
    creds.expired = False
    creds.id_token = None
    return creds


@pytest.fixture
def mock_expired_credentials():
    """Create mock expired credentials for testing refresh flows."""
    creds = MagicMock()
    creds.token = "ya29.expired_token"
    creds.refresh_token = "test_refresh_token"
    creds.token_uri = "https://oauth2.googleapis.com/token"
    creds.client_id = "test_client_id.apps.googleusercontent.com"
    creds.client_secret = "test_client_secret"
    creds.scopes = [
        "https://www.googleapis.com/auth/gmail.readonly",
    ]
    # Use timezone-aware datetime and convert to naive for Google auth compatibility
    creds.expiry = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    creds.valid = False
    creds.expired = True
    creds.id_token = None
    return creds


@pytest.fixture
def mock_oauth_config():
    """Mock OAuth configuration."""
    return {
        "client_id": "test_client_id.apps.googleusercontent.com",
        "client_secret": "test_client_secret",
        "redirect_uri": "http://localhost:8000/oauth2callback",
    }


@pytest.fixture
def oauth_env_vars():
    """Set up OAuth environment variables for testing."""
    os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "test_client_id.apps.googleusercontent.com"
    os.environ["GOOGLE_OAUTH_CLIENT_SECRET"] = "test_client_secret"
    os.environ["GOOGLE_OAUTH_REDIRECT_URI"] = "http://localhost:8000/oauth2callback"
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    yield
    # Cleanup happens in reset_environment fixture


@pytest.fixture
def mock_user_info():
    """Mock user info response from Google API."""
    return {
        "email": "testuser@example.com",
        "id": "123456789",
        "name": "Test User",
        "picture": "https://example.com/photo.jpg",
        "verified_email": True,
    }
