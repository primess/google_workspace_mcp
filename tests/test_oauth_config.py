"""
Tests for OAuth Configuration.

These tests verify the OAuth configuration module which manages
OAuth settings from environment variables and provides version detection.
"""

import os


class TestOAuthConfig:
    """Tests for OAuthConfig class."""

    def test_is_configured_with_env_vars(self, oauth_env_vars):
        """Test is_configured returns True when env vars are set."""
        # Clear the cache to get fresh config
        import auth.oauth_config

        auth.oauth_config._config = None

        # Reload to pick up env vars
        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_configured() is True

    def test_is_configured_without_env_vars(self):
        """Test is_configured returns False when env vars are not set."""
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_configured() is False

    def test_oauth21_enabled_flag(self, oauth_env_vars):
        """Test MCP_ENABLE_OAUTH21 environment variable."""
        os.environ["MCP_ENABLE_OAUTH21"] = "true"

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_oauth21_enabled() is True

    def test_oauth21_disabled_by_default(self):
        """Test OAuth 2.1 is disabled by default."""
        os.environ.pop("MCP_ENABLE_OAUTH21", None)
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        os.environ.pop("GOOGLE_OAUTH_CLIENT_SECRET", None)

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_oauth21_enabled() is False

    def test_stateless_mode_enabled(self, oauth_env_vars):
        """Test stateless mode environment variable."""
        os.environ["WORKSPACE_MCP_STATELESS_MODE"] = "true"
        os.environ["MCP_ENABLE_OAUTH21"] = "true"  # Required for stateless mode

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.stateless_mode is True

    def test_stateless_mode_disabled_by_default(self):
        """Test stateless mode is disabled by default."""
        os.environ.pop("WORKSPACE_MCP_STATELESS_MODE", None)
        os.environ.pop("MCP_ENABLE_OAUTH21", None)

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.stateless_mode is False


class TestOAuthVersionDetection:
    """Tests for OAuth version detection."""

    def test_detect_oauth21_when_enabled(self, oauth_env_vars):
        """Test OAuth 2.1 detection when enabled."""
        os.environ["MCP_ENABLE_OAUTH21"] = "true"

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        # OAuth 2.1 is enabled, but without PKCE params it defaults to oauth20
        # This is the intended behavior for backward compatibility
        # (we don't need to check that since it's a design choice)
        # With PKCE params, it should return oauth21
        version_with_pkce = config.detect_oauth_version(
            {"code_challenge": "test", "code_challenge_method": "S256"}
        )
        assert version_with_pkce == "oauth21"

    def test_detect_oauth20_when_disabled(self, oauth_env_vars):
        """Test OAuth 2.0 detection when 2.1 is disabled."""
        os.environ["MCP_ENABLE_OAUTH21"] = "false"

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        version = config.detect_oauth_version({})
        assert version == "oauth20"


class TestExternalOAuthProvider:
    """Tests for external OAuth provider configuration."""

    def test_external_oauth_provider_enabled(self, oauth_env_vars):
        """Test detection of external OAuth provider mode."""
        os.environ["EXTERNAL_OAUTH21_PROVIDER"] = "true"
        os.environ["MCP_ENABLE_OAUTH21"] = "true"  # Required for external provider

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_external_oauth21_provider() is True

    def test_external_oauth_provider_disabled_by_default(self, oauth_env_vars):
        """Test external OAuth provider is disabled by default."""
        os.environ.pop("EXTERNAL_OAUTH21_PROVIDER", None)
        os.environ.pop("WORKSPACE_MCP_EXTERNAL_OAUTH_PROVIDER", None)

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        assert config.is_external_oauth21_provider() is False


class TestBaseURLConfiguration:
    """Tests for OAuth base URL configuration."""

    def test_default_base_url(self, oauth_env_vars):
        """Test default base URL configuration."""
        os.environ.pop("WORKSPACE_MCP_BASE_URI", None)
        os.environ.pop("PORT", None)
        os.environ.pop("WORKSPACE_MCP_PORT", None)
        os.environ.pop("WORKSPACE_EXTERNAL_URL", None)

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        base_url = config.get_oauth_base_url()
        assert "localhost" in base_url

    def test_custom_base_url(self, oauth_env_vars):
        """Test custom base URL from environment variable."""
        os.environ["WORKSPACE_EXTERNAL_URL"] = "https://custom.domain.com"

        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config

        config = reload_oauth_config()
        base_url = config.get_oauth_base_url()
        assert base_url == "https://custom.domain.com"


class TestConfigReload:
    """Tests for configuration reload functionality."""

    def test_reload_oauth_config(self):
        """Test that reload_oauth_config creates fresh config."""
        import auth.oauth_config

        auth.oauth_config._config = None

        from auth.oauth_config import reload_oauth_config, get_oauth_config

        # Get initial config
        config1 = get_oauth_config()

        # Reload
        config2 = reload_oauth_config()

        # They should be different instances after reload
        assert config1 is not config2
