"""
HashiCorp Vault Client for TMWS
Hestia Security Implementation - Secure Secret Management

This module provides a secure interface to HashiCorp Vault for secret management,
dynamic credentials, and encryption services.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp
import hvac
from cryptography.fernet import Fernet

from ..core.exceptions import SecurityError, ConfigurationError

logger = logging.getLogger(__name__)


class VaultAuthError(SecurityError):
    """Raised when Vault authentication fails"""
    pass


class VaultConnectionError(SecurityError):
    """Raised when Vault connection fails"""
    pass


class VaultClient:
    """
    Secure HashiCorp Vault client with automatic token renewal,
    retry logic, and comprehensive error handling.
    """
    
    def __init__(
        self,
        vault_url: str,
        auth_method: str = "approle",
        mount_point: str = "tmws",
        max_retries: int = 3,
        retry_delay: float = 1.0,
        token_renewal_threshold: int = 300  # 5 minutes
    ):
        self.vault_url = vault_url.rstrip('/')
        self.auth_method = auth_method
        self.mount_point = mount_point
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.token_renewal_threshold = token_renewal_threshold
        
        # Initialize Vault client
        self.client = hvac.Client(url=vault_url)
        
        # Authentication credentials
        self.role_id = os.getenv("VAULT_ROLE_ID")
        self.secret_id = os.getenv("VAULT_SECRET_ID")
        self.token = os.getenv("VAULT_TOKEN")
        
        # Token management
        self._token_expires_at: Optional[datetime] = None
        self._token_renewable = False
        self._auth_lock = asyncio.Lock()
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        
        logger.info(f"Vault client initialized for {vault_url}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def initialize(self) -> None:
        """Initialize the Vault client and authenticate"""
        try:
            # Create HTTP session with security settings
            connector = aiohttp.TCPConnector(
                ssl=True,
                limit=10,
                limit_per_host=5,
                keepalive_timeout=30,
                enable_cleanup_closed=True
            )
            
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "User-Agent": "TMWS-Vault-Client/3.1",
                    "X-Vault-Request": "true"
                }
            )
            
            # Test connection
            await self._test_connection()
            
            # Authenticate
            await self.authenticate()
            
            logger.info("Vault client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            raise VaultConnectionError(f"Vault initialization failed: {e}")
    
    async def close(self) -> None:
        """Close the Vault client and cleanup resources"""
        if self._session:
            await self._session.close()
            self._session = None
        
        logger.info("Vault client closed")
    
    async def _test_connection(self) -> None:
        """Test connection to Vault"""
        try:
            async with self._session.get(f"{self.vault_url}/v1/sys/health") as response:
                if response.status not in [200, 429, 472, 473, 501]:
                    raise VaultConnectionError(f"Vault health check failed: {response.status}")
                
                health_data = await response.json()
                if not health_data.get("initialized", False):
                    raise VaultConnectionError("Vault is not initialized")
                
                if health_data.get("sealed", True):
                    raise VaultConnectionError("Vault is sealed")
                    
        except aiohttp.ClientError as e:
            raise VaultConnectionError(f"Cannot connect to Vault: {e}")
    
    async def authenticate(self) -> None:
        """Authenticate with Vault using configured method"""
        async with self._auth_lock:
            if self.auth_method == "approle":
                await self._authenticate_approle()
            elif self.auth_method == "token":
                await self._authenticate_token()
            elif self.auth_method == "kubernetes":
                await self._authenticate_kubernetes()
            else:
                raise VaultAuthError(f"Unsupported auth method: {self.auth_method}")
            
            logger.info(f"Successfully authenticated with Vault using {self.auth_method}")
    
    async def _authenticate_approle(self) -> None:
        """Authenticate using AppRole method"""
        if not self.role_id or not self.secret_id:
            raise VaultAuthError("AppRole credentials not provided")
        
        auth_data = {
            "role_id": self.role_id,
            "secret_id": self.secret_id
        }
        
        try:
            async with self._session.post(
                f"{self.vault_url}/v1/auth/approle/login",
                json=auth_data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise VaultAuthError(f"AppRole authentication failed: {error_text}")
                
                auth_response = await response.json()
                auth_info = auth_response.get("auth", {})
                
                self.token = auth_info.get("client_token")
                self._token_renewable = auth_info.get("renewable", False)
                
                # Calculate token expiration
                lease_duration = auth_info.get("lease_duration", 3600)
                self._token_expires_at = datetime.utcnow() + timedelta(seconds=lease_duration)
                
                # Set token in hvac client
                self.client.token = self.token
                
        except aiohttp.ClientError as e:
            raise VaultAuthError(f"AppRole authentication request failed: {e}")
    
    async def _authenticate_token(self) -> None:
        """Authenticate using static token"""
        if not self.token:
            raise VaultAuthError("Vault token not provided")
        
        try:
            # Verify token
            async with self._session.get(
                f"{self.vault_url}/v1/auth/token/lookup-self",
                headers={"X-Vault-Token": self.token}
            ) as response:
                if response.status != 200:
                    raise VaultAuthError("Token authentication failed")
                
                token_info = await response.json()
                data = token_info.get("data", {})
                
                self._token_renewable = data.get("renewable", False)
                
                # Calculate token expiration
                expire_time = data.get("expire_time")
                if expire_time:
                    self._token_expires_at = datetime.fromisoformat(
                        expire_time.replace('Z', '+00:00')
                    )
                
                # Set token in hvac client
                self.client.token = self.token
                
        except aiohttp.ClientError as e:
            raise VaultAuthError(f"Token verification failed: {e}")
    
    async def _authenticate_kubernetes(self) -> None:
        """Authenticate using Kubernetes service account"""
        try:
            # Read service account token
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r") as f:
                jwt_token = f.read().strip()
            
            auth_data = {
                "role": "tmws-app",
                "jwt": jwt_token
            }
            
            async with self._session.post(
                f"{self.vault_url}/v1/auth/kubernetes/login",
                json=auth_data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise VaultAuthError(f"Kubernetes authentication failed: {error_text}")
                
                auth_response = await response.json()
                auth_info = auth_response.get("auth", {})
                
                self.token = auth_info.get("client_token")
                self._token_renewable = auth_info.get("renewable", False)
                
                # Calculate token expiration
                lease_duration = auth_info.get("lease_duration", 3600)
                self._token_expires_at = datetime.utcnow() + timedelta(seconds=lease_duration)
                
                # Set token in hvac client
                self.client.token = self.token
                
        except (FileNotFoundError, aiohttp.ClientError) as e:
            raise VaultAuthError(f"Kubernetes authentication failed: {e}")
    
    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid token, renewing if necessary"""
        if not self.token:
            await self.authenticate()
            return
        
        # Check if token is expiring soon
        if (self._token_expires_at and 
            datetime.utcnow() + timedelta(seconds=self.token_renewal_threshold) >= self._token_expires_at):
            
            if self._token_renewable:
                await self._renew_token()
            else:
                # Re-authenticate if token is not renewable
                await self.authenticate()
    
    async def _renew_token(self) -> None:
        """Renew the current Vault token"""
        try:
            async with self._session.post(
                f"{self.vault_url}/v1/auth/token/renew-self",
                headers={"X-Vault-Token": self.token}
            ) as response:
                if response.status != 200:
                    logger.warning("Token renewal failed, re-authenticating")
                    await self.authenticate()
                    return
                
                renewal_response = await response.json()
                auth_info = renewal_response.get("auth", {})
                
                # Update token expiration
                lease_duration = auth_info.get("lease_duration", 3600)
                self._token_expires_at = datetime.utcnow() + timedelta(seconds=lease_duration)
                
                logger.info("Vault token renewed successfully")
                
        except aiohttp.ClientError as e:
            logger.warning(f"Token renewal request failed: {e}, re-authenticating")
            await self.authenticate()
    
    async def _make_vault_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make a request to Vault with retry logic and authentication"""
        await self._ensure_authenticated()
        
        url = f"{self.vault_url}/v1/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self.token}
        
        for attempt in range(self.max_retries):
            try:
                async with self._session.request(
                    method, url, json=data, params=params, headers=headers
                ) as response:
                    
                    if response.status == 403:
                        # Token might be expired, try re-authenticating
                        await self.authenticate()
                        headers["X-Vault-Token"] = self.token
                        continue
                    
                    if response.status >= 400:
                        error_text = await response.text()
                        raise SecurityError(f"Vault request failed: {response.status} - {error_text}")
                    
                    if response.status == 204:  # No content
                        return {}
                    
                    return await response.json()
                    
            except aiohttp.ClientError as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    continue
                raise VaultConnectionError(f"Vault request failed after {self.max_retries} attempts: {e}")
        
        raise VaultConnectionError("Max retries exceeded")
    
    # Secret Management Methods
    
    async def get_secret(self, path: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Get a secret from Vault KV store"""
        full_path = f"{self.mount_point}/data/{path.lstrip('/')}"
        params = {"version": version} if version else None
        
        response = await self._make_vault_request("GET", full_path, params=params)
        
        secret_data = response.get("data", {})
        return secret_data.get("data", {})
    
    async def put_secret(self, path: str, data: Dict[str, Any], cas: Optional[int] = None) -> None:
        """Store a secret in Vault KV store"""
        full_path = f"{self.mount_point}/data/{path.lstrip('/')}"
        
        payload = {"data": data}
        if cas is not None:
            payload["options"] = {"cas": cas}
        
        await self._make_vault_request("POST", full_path, data=payload)
        logger.info(f"Secret stored at {path}")
    
    async def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> None:
        """Delete a secret from Vault KV store"""
        if versions:
            # Delete specific versions
            full_path = f"{self.mount_point}/delete/{path.lstrip('/')}"
            payload = {"versions": versions}
        else:
            # Delete latest version
            full_path = f"{self.mount_point}/data/{path.lstrip('/')}"
            payload = None
        
        await self._make_vault_request("POST", full_path, data=payload)
        logger.info(f"Secret deleted at {path}")
    
    # Database Credentials
    
    async def get_database_credentials(self, role: str = "tmws-role") -> Dict[str, str]:
        """Get dynamic database credentials"""
        response = await self._make_vault_request("GET", f"database/creds/{role}")
        
        creds_data = response.get("data", {})
        return {
            "username": creds_data.get("username"),
            "password": creds_data.get("password"),
            "lease_id": response.get("lease_id"),
            "lease_duration": response.get("lease_duration")
        }
    
    async def revoke_lease(self, lease_id: str) -> None:
        """Revoke a Vault lease"""
        await self._make_vault_request("PUT", "sys/leases/revoke", data={"lease_id": lease_id})
        logger.info(f"Lease {lease_id} revoked")
    
    # Encryption Services
    
    async def encrypt_data(self, plaintext: str, key_name: str = "tmws") -> str:
        """Encrypt data using Vault Transit engine"""
        import base64
        
        encoded_plaintext = base64.b64encode(plaintext.encode()).decode()
        
        response = await self._make_vault_request(
            "POST",
            f"transit/encrypt/{key_name}",
            data={"plaintext": encoded_plaintext}
        )
        
        return response["data"]["ciphertext"]
    
    async def decrypt_data(self, ciphertext: str, key_name: str = "tmws") -> str:
        """Decrypt data using Vault Transit engine"""
        import base64
        
        response = await self._make_vault_request(
            "POST",
            f"transit/decrypt/{key_name}",
            data={"ciphertext": ciphertext}
        )
        
        encoded_plaintext = response["data"]["plaintext"]
        return base64.b64decode(encoded_plaintext).decode()
    
    # PKI Operations
    
    async def generate_certificate(
        self,
        common_name: str,
        role: str = "tmws-internal",
        alt_names: Optional[List[str]] = None,
        ttl: str = "24h"
    ) -> Dict[str, str]:
        """Generate a certificate using Vault PKI"""
        data = {
            "common_name": common_name,
            "ttl": ttl
        }
        
        if alt_names:
            data["alt_names"] = ",".join(alt_names)
        
        response = await self._make_vault_request("POST", f"pki/issue/{role}", data=data)
        
        cert_data = response.get("data", {})
        return {
            "certificate": cert_data.get("certificate"),
            "private_key": cert_data.get("private_key"),
            "ca_chain": cert_data.get("ca_chain"),
            "serial_number": cert_data.get("serial_number"),
            "lease_id": response.get("lease_id")
        }
    
    # Health and Status
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check of the Vault client"""
        try:
            await self._ensure_authenticated()
            
            # Test a simple operation
            await self._make_vault_request("GET", "sys/health")
            
            return {
                "status": "healthy",
                "authenticated": True,
                "token_expires_at": self._token_expires_at.isoformat() if self._token_expires_at else None,
                "vault_url": self.vault_url
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "authenticated": False,
                "vault_url": self.vault_url
            }


# Factory function
def create_vault_client() -> VaultClient:
    """Create a Vault client with configuration from environment"""
    vault_url = os.getenv("TMWS_VAULT_URL", "https://vault:8200")
    auth_method = os.getenv("TMWS_VAULT_AUTH_METHOD", "approle")
    mount_point = os.getenv("TMWS_VAULT_MOUNT_POINT", "tmws")
    
    if not vault_url:
        raise ConfigurationError("TMWS_VAULT_URL environment variable is required")
    
    return VaultClient(
        vault_url=vault_url,
        auth_method=auth_method,
        mount_point=mount_point
    )


# Global client instance (singleton)
_vault_client: Optional[VaultClient] = None


async def get_vault_client() -> VaultClient:
    """Get or create the global Vault client instance"""
    global _vault_client
    
    if _vault_client is None:
        _vault_client = create_vault_client()
        await _vault_client.initialize()
    
    return _vault_client


async def close_vault_client() -> None:
    """Close the global Vault client instance"""
    global _vault_client
    
    if _vault_client:
        await _vault_client.close()
        _vault_client = None