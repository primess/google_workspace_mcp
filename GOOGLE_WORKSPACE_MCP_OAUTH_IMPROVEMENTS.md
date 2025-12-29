# Google Workspace MCP OAuth Improvements Analysis

## Overview

This document analyzes changes from AI-Experiments PR #44 and PR #45 that should be considered for integration into the google_workspace_mcp project (PR #1).

## Context

- **PR #1** (google_workspace_mcp): Adds OAuth test suite (71 tests) and documentation for the existing OAuth 2.1 implementation
- **PR #44** (AI-Experiments): Session management, LLM understanding, cloud auth, security fixes (merged)
- **PR #45** (AI-Experiments): OAuth credential override configuration improvements (open)

## Recommended Changes from AI-Experiments PRs

### 1. OAuth Credential Override Configuration

**Source:** PR #45 (`backend/app/config.py`, `backend/app/mcp_credentials_manager.py`)

**Change Description:**
Add a configurable flag `IS_OAUTH_OVERRIDE_CREDENTIALS_JSON` that controls credential precedence:
- When `true` (default): OAuth flow credentials take priority over `MCP_CREDENTIALS_JSON`
- When `false`: `MCP_CREDENTIALS_JSON` can override existing OAuth credentials

**Why it's needed:**
- Provides flexibility for different deployment scenarios
- In development: Interactive OAuth is preferred
- In CI/CD or cloud: Environment variable credentials should be usable even if OAuth credentials exist
- Supports both single-user and multi-user deployment patterns

**Implementation:**
```python
# In config or environment
IS_OAUTH_OVERRIDE_CREDENTIALS_JSON = os.getenv("IS_OAUTH_OVERRIDE_CREDENTIALS_JSON", "true").lower() == "true"
```

**Tradeoffs:**
- **Pro:** Greater flexibility for different deployment scenarios
- **Pro:** Explicit control over credential source
- **Con:** Additional configuration to manage
- **Con:** Could lead to confusion if not documented properly

---

### 2. Enhanced Credential Format Handling

**Source:** PR #45 (`backend/app/mcp_credentials_manager.py`, `backend/app/tests/test_mcp_credentials.py`)

**Change Description:**
Improve credential handling to support multiple formats and ensure all required fields are present for token refresh:

1. **Support both `access_token` and `token` field names**
   - Google OAuth responses use `access_token`
   - google-auth library uses `token`
   - Handle both seamlessly

2. **Calculate expiry from `expires_in`**
   - When `expiry` is not provided, calculate it from `expires_in` seconds
   - Store in ISO format for compatibility

3. **Parse scope strings to lists**
   - Google OAuth returns space-separated scope strings
   - google-auth library expects lists
   - Parse automatically during credential storage

4. **Ensure all refresh-required fields are present**
   - `refresh_token`, `token_uri`, `client_id`, `client_secret`, `scopes`, `expiry`
   - Required for automatic token refresh

**Why it's needed:**
- The MCP server must be able to refresh tokens automatically
- Different OAuth sources provide credentials in different formats
- Missing fields cause silent token refresh failures

**Implementation highlights:**
```python
from datetime import datetime, timedelta, timezone

def save_credentials(user_email, tokens, client_id, client_secret):
    # Handle both access_token and token field names
    token = tokens.get("access_token") or tokens.get("token")
    
    # Calculate expiry from expires_in if not provided
    expiry = None
    if tokens.get("expiry"):
        expiry = tokens["expiry"]
    elif tokens.get("expires_in"):
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=tokens["expires_in"])).isoformat()
    
    # Parse scope string to list
    scopes = tokens.get("scope", "").split() if isinstance(tokens.get("scope"), str) else tokens.get("scopes", [])
    
    # Ensure complete credential structure
    credential_data = {
        "token": token,
        "refresh_token": tokens.get("refresh_token"),
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": scopes,
        "expiry": expiry,
    }
```

**Tradeoffs:**
- **Pro:** More robust credential handling
- **Pro:** Better compatibility with different OAuth flows
- **Pro:** Reliable token refresh
- **Con:** Slightly more complex credential storage logic
- **Con:** Need to handle backward compatibility with existing credential files

---

### 3. Credential Management Tests

**Source:** PR #45 (`backend/app/tests/test_mcp_credentials.py`)

**Change Description:**
Comprehensive test suite for credential management including:

1. **TestCredentialFormat** - Validates credential structure
   - Complete structure with all required fields
   - Both token field name variants
   - Expiry calculation
   - Scope parsing

2. **TestOAuthOverrideBehavior** - Tests precedence rules
   - OAuth override true skips MCP_CREDENTIALS_JSON
   - OAuth override false allows overwriting
   - No existing credentials always uses MCP_CREDENTIALS_JSON

3. **TestCredentialRefreshCapability** - Ensures refresh works
   - All required fields for Google OAuth refresh
   - Credentials loadable by google-auth library

**Why it's needed:**
- Credential handling is critical for MCP server operation
- Edge cases in credential format cause silent failures
- Tests ensure changes don't break existing functionality

**Tradeoffs:**
- **Pro:** High confidence in credential handling
- **Pro:** Catches regressions early
- **Pro:** Documents expected behavior
- **Con:** Additional test maintenance

---

## Changes NOT Recommended for google_workspace_mcp

### 1. Open Redirect Security Fix (from PR #44)

**Why not applicable:**
- This fix is for the AI-Experiments backend FastAPI auth endpoints
- google_workspace_mcp uses FastMCP's built-in OAuth provider
- Different authentication flow and architecture

### 2. Session/Memory Management (from PR #44)

**Why not applicable:**
- Session management is for the AI agent orchestrator
- MCP servers are stateless by design
- OAuth21SessionStore in google_workspace_mcp already handles session isolation

### 3. LLM-Based Understanding (from PR #44)

**Why not applicable:**
- This is AI agent behavior, not MCP server functionality
- MCP servers provide tools, not AI reasoning

---

## Implementation Priority

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| High | OAuth Credential Override Config | Low | High |
| High | Enhanced Credential Format Handling | Medium | High |
| Medium | Credential Management Tests | Medium | Medium |

---

## Security Considerations

1. **Credential Storage Security**
   - Continue using 0o600 file permissions
   - Support encrypted storage backends (Valkey)
   - Never log credential values

2. **Override Configuration**
   - Default to OAuth taking priority (more secure)
   - Environment variable override requires explicit opt-in

3. **Token Handling**
   - Validate tokens before storage
   - Handle refresh errors gracefully
   - Clear invalid credentials

---

## Implementation Prompt for google_workspace_mcp

The following prompt is formatted for easy copy-paste to implement these changes in the google_workspace_mcp project:

---

<details>
<summary><strong>📋 Click to expand implementation prompt (copy the content below)</strong></summary>

```text
Implement OAuth credential management improvements in the google_workspace_mcp project.

Reference the GOOGLE_WORKSPACE_MCP_OAUTH_IMPROVEMENTS.md document for full context and rationale.

## Summary of Changes

The changes improve credential handling for cloud deployment scenarios where credentials may come from environment variables (MCP_CREDENTIALS_JSON) or interactive OAuth flows.

## 1. Add OAuth Credential Override Configuration

Add support for IS_OAUTH_OVERRIDE_CREDENTIALS_JSON environment variable in auth/oauth_config.py:

- When "true" (default): Interactive OAuth flow credentials take priority over MCP_CREDENTIALS_JSON
- When "false": MCP_CREDENTIALS_JSON can overwrite existing OAuth credentials

This allows flexibility for different deployment scenarios (development vs CI/CD).

Example implementation in OAuthConfig class:
```python
self.is_oauth_override_credentials_json = (
    os.getenv("IS_OAUTH_OVERRIDE_CREDENTIALS_JSON", "true").lower() == "true"
)
```

## 2. Enhance Credential Format Handling

Update credential storage in auth/google_auth.py or auth/credential_store.py to:

1. Accept both "access_token" and "token" field names from OAuth responses
2. Calculate "expiry" from "expires_in" when expiry is not explicitly provided  
3. Parse space-separated scope strings into lists
4. Ensure all fields required for token refresh are present:
   - token, refresh_token, token_uri, client_id, client_secret, scopes, expiry

Example token extraction:
```python
token = tokens.get("access_token") or tokens.get("token")
```

Example expiry calculation:
```python
from datetime import datetime, timedelta, timezone

expiry = None
if tokens.get("expiry"):
    expiry = tokens["expiry"]
elif tokens.get("expires_in"):
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=tokens["expires_in"])).isoformat()
```

Example scope parsing:
```python
if isinstance(tokens.get("scope"), str):
    scopes = tokens["scope"].split()
else:
    scopes = tokens.get("scopes", [])
```

## 3. Add Credential Management Tests

Create tests/test_credential_management.py with tests for:

### TestCredentialFormat
- test_save_credentials_creates_complete_structure
- test_save_credentials_handles_both_token_field_names  
- test_save_credentials_calculates_expiry_from_expires_in
- test_save_credentials_parses_scope_string_to_list

### TestOAuthOverrideBehavior
- test_oauth_override_true_skips_mcp_credentials_json
- test_oauth_override_false_allows_mcp_credentials_json
- test_no_existing_credentials_always_uses_mcp_credentials_json

### TestCredentialRefreshCapability  
- test_saved_credentials_have_refresh_requirements
- test_credentials_can_be_loaded_by_google_auth_library

## Code Quality Requirements

Apply ruff formatting to all changed files:
```bash
ruff check --fix .
ruff format .
```

Run the full test suite including new tests:
```bash
pytest tests/ -v
```

## Expected Test Results

1. Credential format validation works correctly
2. OAuth override behavior respects the IS_OAUTH_OVERRIDE_CREDENTIALS_JSON configuration
3. Token refresh capability is maintained - credentials include all required fields
4. Existing tests continue to pass (no regressions)
```

</details>

---

### Quick Copy Version

For convenience, here's a minimal version of the prompt:

```
Implement OAuth credential improvements in google_workspace_mcp:

1. Add IS_OAUTH_OVERRIDE_CREDENTIALS_JSON env var in auth/oauth_config.py
   - Default "true": OAuth credentials take priority over MCP_CREDENTIALS_JSON
   - "false": MCP_CREDENTIALS_JSON can overwrite OAuth credentials

2. Enhance credential format handling in auth/google_auth.py:
   - Accept both "access_token" and "token" field names
   - Calculate expiry from expires_in when not provided
   - Parse scope strings to lists
   - Ensure all refresh-required fields present

3. Add tests in tests/test_credential_management.py:
   - Credential format validation
   - OAuth override behavior
   - Token refresh capability

Apply ruff formatting and run pytest.

See docs/GOOGLE_WORKSPACE_MCP_OAUTH_IMPROVEMENTS.md for full rationale.
```
