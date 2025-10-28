"""
GeoIP Service for Security Audit System.

This service handles IP address geolocation using MaxMind GeoLite2 database.
Extracted from AsyncSecurityAuditLogger as part of Phase 4.2 refactoring.
"""

import asyncio
import logging
from pathlib import Path

import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)


class GeoIPService:
    """
    Service for IP address geolocation.

    Uses MaxMind GeoLite2-City database to lookup location information.
    GeoIP is optional - service gracefully degrades if database unavailable.
    """

    def __init__(self, geoip_db_path: str | Path | None = None):
        """
        Initialize GeoIP service.

        Args:
            geoip_db_path: Path to GeoLite2-City.mmdb file.
                          If None, uses default path /usr/local/share/GeoIP/GeoLite2-City.mmdb
        """
        self.geoip_db_path = Path(geoip_db_path) if geoip_db_path else Path(
            "/usr/local/share/GeoIP/GeoLite2-City.mmdb"
        )
        self.geoip_reader: geoip2.database.Reader | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize GeoIP database reader (optional).

        If database is not available, service will operate in degraded mode
        (location tracking disabled but other audit functions continue).
        """
        if self._initialized:
            logger.debug("GeoIP service already initialized")
            return

        try:
            if self.geoip_db_path.exists():
                # Load database in thread pool (blocking I/O)
                loop = asyncio.get_event_loop()
                self.geoip_reader = await loop.run_in_executor(
                    None, geoip2.database.Reader, str(self.geoip_db_path)
                )
                logger.info(f"✅ GeoIP database loaded from {self.geoip_db_path}")
                self._initialized = True
            else:
                logger.info(
                    f"ℹ️  GeoIP database not found at {self.geoip_db_path} - "
                    "location tracking disabled"
                )
                self.geoip_reader = None
                self._initialized = True

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            # GeoIP is optional - log warning and continue without location tracking
            logger.warning(
                f"⚠️  Failed to load GeoIP database (location tracking disabled): {e}",
                exc_info=True,
                extra={"geoip_path": str(self.geoip_db_path)},
            )
            self.geoip_reader = None
            self._initialized = True

    async def lookup(self, ip_address: str) -> dict[str, str] | None:
        """
        Lookup location information for IP address.

        Args:
            ip_address: IPv4 or IPv6 address to lookup

        Returns:
            Location info dict with keys:
                - country: Country name (e.g., "United States")
                - country_code: ISO 3166-1 alpha-2 code (e.g., "US")
                - city: City name (e.g., "San Francisco")
                - region: Region/state name (e.g., "California")
                - latitude: Latitude as string (e.g., "37.7749")
                - longitude: Longitude as string (e.g., "-122.4194")

            Returns None if:
                - GeoIP reader not initialized
                - IP lookup fails (private IP, invalid, etc.)
                - Unexpected error occurs

        Note:
            Runs GeoIP lookup in thread pool to avoid blocking event loop.
        """
        if not self._initialized:
            logger.warning("GeoIP service not initialized - call initialize() first")
            return None

        if not self.geoip_reader:
            # Service running in degraded mode (no database)
            return None

        try:
            # Run GeoIP lookup in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, self.geoip_reader.city, ip_address
            )

            return {
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "XX",
                "city": response.city.name or "Unknown",
                "region": response.subdivisions.most_specific.name or "Unknown",
                "latitude": (
                    str(response.location.latitude)
                    if response.location.latitude
                    else None
                ),
                "longitude": (
                    str(response.location.longitude)
                    if response.location.longitude
                    else None
                ),
            }

        except (KeyboardInterrupt, SystemExit):
            raise
        except (geoip2.errors.AddressNotFoundError, ValueError):
            # Expected errors for private/invalid IPs
            logger.debug(
                f"IP address not found in GeoIP database: {ip_address}",
                extra={"ip_address": ip_address}
            )
            return {"country": "Unknown", "country_code": "XX"}
        except Exception as e:
            # Unexpected GeoIP errors - log but don't fail audit logging
            logger.warning(
                f"⚠️  GeoIP lookup failed for {ip_address} (non-critical): {e}",
                exc_info=False,  # Don't spam with stack traces for geolocation failures
                extra={"ip_address": ip_address},
            )
            return None

    async def cleanup(self) -> None:
        """
        Cleanup GeoIP resources.

        Closes database reader if open.
        """
        if self.geoip_reader:
            try:
                # Close in thread pool (potentially blocking)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.geoip_reader.close)
                logger.debug("GeoIP reader closed")
            except Exception as e:
                logger.warning(f"Error closing GeoIP reader: {e}", exc_info=True)
            finally:
                self.geoip_reader = None
                self._initialized = False

    @property
    def is_available(self) -> bool:
        """
        Check if GeoIP service is available.

        Returns:
            True if GeoIP database is loaded and operational, False otherwise
        """
        return self._initialized and self.geoip_reader is not None
