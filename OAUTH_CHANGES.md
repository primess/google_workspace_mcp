# OAuth 2.1 Implementation Changes

This document explains the OAuth implementation changes in the Google Workspace MCP server, why they are needed, and what tradeoffs they introduce.

## Overview

The Google Workspace MCP server provides a comprehensive OAuth implementation supporting both OAuth 2.0 and OAuth 2.1 authentication flows. The implementation includes several key components:

1. **Credential Store API** (`auth/credential_store.py`)
2. **External OAuth Provider** (`auth/external_oauth_provider.py`)
3. **Google Auth Module** (`auth/google_auth.py`)
4. **Service Decorator** (`auth/service_decorator.py`)
5. **Server Configuration** (`core/server.py`)

## Why These Changes Are Good/Needed

### 1. Credential Store API (`credential_store.py`)

**Purpose:** Provides a standardized interface for credential storage and retrieval with pluggable backends.

**Benefits:**
- **Abstraction**: Abstract base class (`CredentialStore`) enables different storage backends without changing consumer code
- **Security**: Centralized credential management reduces the risk of credential leaks
- **Timezone handling**: Properly converts timezone-aware expiry times to naive datetimes for Google auth library compatibility
- **Multi-user support**: Supports multiple user credentials with listing functionality

**Tradeoffs:**
- Adds another layer of abstraction
- File-based storage may not scale for very large deployments (consider Valkey/Redis for production)

### 2. External OAuth Provider (`external_oauth_provider.py`)

**Purpose:** Extends FastMCP's GoogleProvider to support external OAuth flows where access tokens (ya29.*) are issued by external systems.

**Benefits:**
- **Flexibility**: Allows integration with external identity providers
- **Validation**: Validates ya29.* access tokens by calling Google's userinfo API
- **Compatibility**: Maintains compatibility with standard JWT ID tokens by delegating to parent class

**Tradeoffs:**
- Additional network call for ya29.* token validation (userinfo API)
- Requires proper error handling for token validation failures

### 3. Google Auth Module (`google_auth.py`)

**Purpose:** Core OAuth authentication logic including flow creation, callback handling, and credential management.

**Benefits:**
- **Environment variable support**: Supports both environment variables and file-based client secrets
- **Single-user mode**: Simplifies development with `--single-user` flag
- **OAuth 2.1 session store integration**: Centralized session management
- **Automatic refresh**: Handles token refresh transparently

**Tradeoffs:**
- Complex logic to support multiple authentication paths
- Must handle both stateless and stateful modes

### 4. Service Decorator (`service_decorator.py`)

**Purpose:** Decorator that automatically handles Google service authentication and injection.

**Benefits:**
- **DRY principle**: Eliminates repeated authentication boilerplate in tools
- **Automatic OAuth version detection**: Transparently handles OAuth 2.0 and 2.1
- **Graceful error handling**: Provides user-friendly messages for token refresh errors
- **Signature modification**: In OAuth 2.1 mode, removes `user_google_email` parameter from function signatures

**Tradeoffs:**
- Decorator magic may be harder to debug
- Signature modification in OAuth 2.1 mode changes API contract

### 5. Server Configuration (`core/server.py`)

**Purpose:** Configures the authentication provider for HTTP transport with support for multiple storage backends.

**Benefits:**
- **Multiple storage backends**: Supports Valkey, disk, and memory storage
- **Encryption**: Uses Fernet encryption for stored credentials
- **JWT signing key derivation**: Derives signing keys from client secret or custom key
- **External OAuth provider mode**: Supports scenarios where protocol-level auth is disabled

**Tradeoffs:**
- Complex initialization logic
- Multiple configuration options can be confusing

## Security Considerations

The implementation includes several security features:

1. **PKCE Support**: OAuth 2.1 mode requires PKCE for enhanced security
2. **Encrypted Storage**: Credentials can be encrypted using Fernet
3. **Session Validation**: `get_credentials_with_validation()` ensures sessions can only access their own credentials
4. **OAuth State Validation**: Prevents CSRF attacks in OAuth flows
5. **Token Refresh Error Handling**: Gracefully handles expired/revoked tokens

## Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GOOGLE_OAUTH_CLIENT_ID` | OAuth 2.0 client ID | None |
| `GOOGLE_OAUTH_CLIENT_SECRET` | OAuth 2.0 client secret | None |
| `MCP_ENABLE_OAUTH21` | Enable OAuth 2.1 mode | `false` |
| `EXTERNAL_OAUTH21_PROVIDER` | Enable external OAuth 2.1 provider | `false` |
| `WORKSPACE_MCP_STATELESS_MODE` | Enable stateless mode | `false` |
| `WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND` | Storage backend (`valkey`, `disk`, `memory`) | Default |
| `WORKSPACE_EXTERNAL_URL` | External URL for reverse proxy | None |

## Test Coverage

The test suite includes 71 tests covering:

- Credential store operations (storage, retrieval, deletion, listing)
- External OAuth provider token verification
- OAuth 2.1 session store functionality
- OAuth configuration management
- Service decorator functionality
- Token refresh error handling
- Scope resolution and configuration

## Future Improvements

Potential areas for enhancement:

1. **Additional storage backends**: Support for other databases (PostgreSQL, MongoDB)
2. **Token rotation**: Implement automatic token rotation for enhanced security
3. **Audit logging**: Add logging for credential access and modifications
4. **Rate limiting**: Implement rate limiting for OAuth flows
5. **Multi-tenant support**: Enhanced support for multi-tenant scenarios
