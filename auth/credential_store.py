"""
Credential Store API for Google Workspace MCP

This module provides a standardized interface for credential storage and retrieval,
supporting multiple backends configurable via environment variables.
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)


class CredentialStore(ABC):
    """Abstract base class for credential storage."""

    @abstractmethod
    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """
        Get credentials for a user by email.

        Args:
            user_email: User's email address

        Returns:
            Google Credentials object or None if not found
        """
        pass

    @abstractmethod
    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """
        Store credentials for a user.

        Args:
            user_email: User's email address
            credentials: Google Credentials object to store

        Returns:
            True if successfully stored, False otherwise
        """
        pass

    @abstractmethod
    def delete_credential(self, user_email: str) -> bool:
        """
        Delete credentials for a user.

        Args:
            user_email: User's email address

        Returns:
            True if successfully deleted, False otherwise
        """
        pass

    @abstractmethod
    def list_users(self) -> List[str]:
        """
        List all users with stored credentials.

        Returns:
            List of user email addresses
        """
        pass

    def store_raw_tokens(
        self,
        user_email: str,
        tokens: Dict[str, Any],
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> bool:
        """
        Store credentials from raw token data (e.g., from OAuth responses).

        This method handles various token formats:
        - Accepts both "access_token" and "token" field names
        - Calculates "expiry" from "expires_in" when not provided
        - Parses space-separated scope strings into lists
        - Ensures all required fields for token refresh are present

        Args:
            user_email: User's email address
            tokens: Raw token dictionary from OAuth response
            client_id: OAuth client ID (optional, may be in tokens)
            client_secret: OAuth client secret (optional, may be in tokens)

        Returns:
            True if successfully stored, False otherwise
        """
        # Handle both access_token and token field names
        token = tokens.get("access_token") or tokens.get("token")

        # Calculate expiry from expires_in if not provided
        expiry = None
        if tokens.get("expiry"):
            expiry = tokens["expiry"]
        elif tokens.get("expires_in"):
            expiry = (
                datetime.now(timezone.utc) + timedelta(seconds=tokens["expires_in"])
            ).isoformat()

        # Parse scope string to list
        if isinstance(tokens.get("scope"), str):
            scopes = tokens["scope"].split()
        else:
            scopes = tokens.get("scopes", [])

        # Get client credentials from tokens or parameters
        final_client_id = client_id or tokens.get("client_id")
        final_client_secret = client_secret or tokens.get("client_secret")

        # Build complete credential structure
        credential_data = {
            "token": token,
            "refresh_token": tokens.get("refresh_token"),
            "token_uri": tokens.get("token_uri", "https://oauth2.googleapis.com/token"),
            "client_id": final_client_id,
            "client_secret": final_client_secret,
            "scopes": scopes,
            "expiry": expiry,
        }

        # Parse expiry for Credentials object
        expiry_dt = None
        if expiry:
            try:
                expiry_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                # Ensure timezone-naive for Google auth library
                if expiry_dt.tzinfo is not None:
                    expiry_dt = expiry_dt.replace(tzinfo=None)
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse expiry time: {e}")

        credentials = Credentials(
            token=credential_data["token"],
            refresh_token=credential_data.get("refresh_token"),
            token_uri=credential_data.get("token_uri"),
            client_id=credential_data.get("client_id"),
            client_secret=credential_data.get("client_secret"),
            scopes=credential_data.get("scopes"),
            expiry=expiry_dt,
        )

        return self.store_credential(user_email, credentials)


class LocalDirectoryCredentialStore(CredentialStore):
    """Credential store that uses local JSON files for storage."""

    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize the local JSON credential store.

        Args:
            base_dir: Base directory for credential files. If None, uses the directory
                     configured by the GOOGLE_MCP_CREDENTIALS_DIR environment variable,
                     or defaults to ~/.google_workspace_mcp/credentials if the environment
                     variable is not set.
        """
        if base_dir is None:
            if os.getenv("GOOGLE_MCP_CREDENTIALS_DIR"):
                base_dir = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")
            else:
                home_dir = os.path.expanduser("~")
                if home_dir and home_dir != "~":
                    base_dir = os.path.join(
                        home_dir, ".google_workspace_mcp", "credentials"
                    )
                else:
                    base_dir = os.path.join(os.getcwd(), ".credentials")

        self.base_dir = base_dir
        logger.info(f"LocalJsonCredentialStore initialized with base_dir: {base_dir}")

    def _get_credential_path(self, user_email: str) -> str:
        """Get the file path for a user's credentials."""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
            logger.info(f"Created credentials directory: {self.base_dir}")
        return os.path.join(self.base_dir, f"{user_email}.json")

    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """Get credentials from local JSON file."""
        creds_path = self._get_credential_path(user_email)

        if not os.path.exists(creds_path):
            logger.debug(f"No credential file found for {user_email} at {creds_path}")
            return None

        try:
            with open(creds_path, "r") as f:
                creds_data = json.load(f)

            # Parse expiry if present
            expiry = None
            if creds_data.get("expiry"):
                try:
                    expiry = datetime.fromisoformat(creds_data["expiry"])
                    # Ensure timezone-naive datetime for Google auth library compatibility
                    if expiry.tzinfo is not None:
                        expiry = expiry.replace(tzinfo=None)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse expiry time for {user_email}: {e}")

            credentials = Credentials(
                token=creds_data.get("token"),
                refresh_token=creds_data.get("refresh_token"),
                token_uri=creds_data.get("token_uri"),
                client_id=creds_data.get("client_id"),
                client_secret=creds_data.get("client_secret"),
                scopes=creds_data.get("scopes"),
                expiry=expiry,
            )

            logger.debug(f"Loaded credentials for {user_email} from {creds_path}")
            return credentials

        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.error(
                f"Error loading credentials for {user_email} from {creds_path}: {e}"
            )
            return None

    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """Store credentials to local JSON file."""
        creds_path = self._get_credential_path(user_email)

        creds_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
        }

        try:
            with open(creds_path, "w") as f:
                json.dump(creds_data, f, indent=2)
            logger.info(f"Stored credentials for {user_email} to {creds_path}")
            return True
        except IOError as e:
            logger.error(
                f"Error storing credentials for {user_email} to {creds_path}: {e}"
            )
            return False

    def delete_credential(self, user_email: str) -> bool:
        """Delete credential file for a user."""
        creds_path = self._get_credential_path(user_email)

        try:
            if os.path.exists(creds_path):
                os.remove(creds_path)
                logger.info(f"Deleted credentials for {user_email} from {creds_path}")
                return True
            else:
                logger.debug(
                    f"No credential file to delete for {user_email} at {creds_path}"
                )
                return True  # Consider it a success if file doesn't exist
        except IOError as e:
            logger.error(
                f"Error deleting credentials for {user_email} from {creds_path}: {e}"
            )
            return False

    def list_users(self) -> List[str]:
        """List all users with credential files."""
        if not os.path.exists(self.base_dir):
            return []

        users = []
        try:
            for filename in os.listdir(self.base_dir):
                if filename.endswith(".json"):
                    user_email = filename[:-5]  # Remove .json extension
                    users.append(user_email)
            logger.debug(
                f"Found {len(users)} users with credentials in {self.base_dir}"
            )
        except OSError as e:
            logger.error(f"Error listing credential files in {self.base_dir}: {e}")

        return sorted(users)


# Global credential store instance
_credential_store: Optional[CredentialStore] = None


def get_credential_store() -> CredentialStore:
    """
    Get the global credential store instance.

    Returns:
        Configured credential store instance
    """
    global _credential_store

    if _credential_store is None:
        # always use LocalJsonCredentialStore as the default
        # Future enhancement: support other backends via environment variables
        _credential_store = LocalDirectoryCredentialStore()
        logger.info(f"Initialized credential store: {type(_credential_store).__name__}")

    return _credential_store


def set_credential_store(store: CredentialStore):
    """
    Set the global credential store instance.

    Args:
        store: Credential store instance to use
    """
    global _credential_store
    _credential_store = store
    logger.info(f"Set credential store: {type(store).__name__}")
