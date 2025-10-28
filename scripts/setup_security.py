#!/usr/bin/env python3
"""
TMWS Security Setup Script
Hestia's Production Security Initialization

This script initializes the TMWS security system:
- Generates secure keys and configuration
- Sets up default security policies
- Registers Trinitas core agents
- Validates security configuration
"""

import asyncio
import logging
import os
import secrets
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.config import Settings, settings
from security.access_control import (
    AccessDecision,
    AccessPolicy,
    ActionType,
    ResourceType,
    create_access_control_manager,
)
from security.agent_auth import AgentAccessLevel, create_agent_authenticator
from security.data_encryption import DataClassification, create_encryption_service

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SecuritySetup:
    """Security system initialization and setup.

    Note: Configuration is now loaded from environment variables via Pydantic Settings.
    No YAML config file is required. Set TMWS_* environment variables instead.
    """

    def __init__(self, _config_path: str = None):
        # Config path parameter is deprecated but kept for backward compatibility
        if _config_path:
            logger.warning(
                "Config file path is deprecated. Using environment variables instead. "
                "Set TMWS_SECRET_KEY and other TMWS_* variables."
            )

        self.settings = settings
        self.setup_results: dict[str, Any] = {}

    async def run_setup(self) -> dict[str, Any]:
        """Run complete security setup process."""
        logger.info("🔥 Starting TMWS Security Setup (Hestia's Paranoid Edition)")

        try:
            # Step 1: Generate and validate security keys
            await self._generate_security_keys()

            # Step 2: Initialize security services
            await self._initialize_security_services()

            # Step 3: Set up default policies
            await self._setup_default_policies()

            # Step 4: Register Trinitas agents
            await self._register_trinitas_agents()

            # Step 5: Validate configuration
            await self._validate_security_config()

            # Step 6: Generate configuration files
            await self._generate_config_files()

            logger.info("✅ Security setup completed successfully")
            self.setup_results["status"] = "success"

        except Exception as e:
            logger.error(f"❌ Security setup failed: {e}")
            self.setup_results["status"] = "failed"
            self.setup_results["error"] = str(e)
            raise

        return self.setup_results

    async def _generate_security_keys(self):
        """Generate cryptographic keys for the system.

        Note: Keys are generated and stored in results. You must set them as
        environment variables (TMWS_SECRET_KEY) for them to persist.
        """
        logger.info("🔑 Generating security keys...")

        # Generate secret key for JWT (if not already set)
        if not self.settings.secret_key or len(self.settings.secret_key) < 32:
            secret_key = secrets.token_urlsafe(64)
            logger.info("Generated new secret key (set TMWS_SECRET_KEY to persist)")
        else:
            secret_key = self.settings.secret_key
            logger.info("Using existing secret key from environment")

        # Generate encryption master key (stored in results for .env generation)
        encryption_key = secrets.token_urlsafe(64)

        # Store in results for later use
        self.setup_results["secret_key"] = secret_key
        self.setup_results["encryption_key"] = encryption_key

        logger.info("✅ Security keys generated")

    async def _initialize_security_services(self):
        """Initialize security service instances."""
        logger.info("🛡️ Initializing security services...")

        # Initialize agent authenticator (use generated or existing key)
        secret_key = self.setup_results["secret_key"]
        self.authenticator = create_agent_authenticator(secret_key)

        # Initialize access control
        self.access_control = create_access_control_manager()

        # Initialize encryption service (use generated key)
        encryption_key = self.setup_results["encryption_key"]
        self.encryption = create_encryption_service(encryption_key)

        self.setup_results["services_initialized"] = True
        logger.info("✅ Security services initialized")

    async def _setup_default_policies(self):
        """Set up comprehensive default security policies."""
        logger.info("📋 Setting up default security policies...")

        policies_created = 0

        # Trinitas agents special access policy
        trinitas_policy = AccessPolicy(
            policy_id="trinitas_core_agents",
            name="Trinitas Core Agents Access",
            description="Enhanced access for Trinitas core system agents",
            resource_types={
                ResourceType.MEMORY,
                ResourceType.TASK,
                ResourceType.WORKFLOW,
                ResourceType.LEARNING_PATTERN,
            },
            actions={ActionType.READ, ActionType.CREATE, ActionType.UPDATE, ActionType.EXECUTE},
            agent_patterns=[
                r"athena-conductor",
                r"artemis-optimizer",
                r"hestia-auditor",
                r"eris-coordinator",
                r"hera-strategist",
                r"muses-documenter",
            ],
            conditions=[],
            decision=AccessDecision.ALLOW,
            priority=250,
            created_by="setup_system",
        )
        self.access_control.add_policy(trinitas_policy)
        policies_created += 1

        # Namespace strict isolation policy
        namespace_isolation = AccessPolicy(
            policy_id="strict_namespace_isolation",
            name="Strict Namespace Isolation",
            description="Prevent cross-namespace data access except for admin agents",
            resource_types={ResourceType.MEMORY, ResourceType.TASK},
            actions={ActionType.READ, ActionType.UPDATE, ActionType.DELETE},
            agent_patterns=[r".*"],
            conditions=[
                {"type": "resource_owner", "require_ownership": False},
                {"type": "agent_namespace", "allowed_namespaces": ["trinitas", "system"]},
            ],
            decision=AccessDecision.DENY,
            priority=180,
            created_by="setup_system",
        )
        self.access_control.add_policy(namespace_isolation)
        policies_created += 1

        # High-sensitivity data protection
        sensitive_data_policy = AccessPolicy(
            policy_id="sensitive_data_protection",
            name="Sensitive Data Protection",
            description="Require elevated privileges for sensitive data",
            resource_types={ResourceType.MEMORY, ResourceType.LEARNING_PATTERN},
            actions={ActionType.READ, ActionType.UPDATE, ActionType.DELETE},
            agent_patterns=[r".*"],
            conditions=[{"type": "data_classification", "max_classification": "restricted"}],
            decision=AccessDecision.REQUIRE_APPROVAL,
            priority=200,
            created_by="setup_system",
        )
        self.access_control.add_policy(sensitive_data_policy)
        policies_created += 1

        # Rate limiting for non-system agents
        rate_limit_policy = AccessPolicy(
            policy_id="agent_rate_limiting",
            name="Agent Request Rate Limiting",
            description="Limit request frequency for non-system agents",
            resource_types=set(ResourceType),
            actions=set(ActionType),
            agent_patterns=[r"^(?!system-|.*-admin$).*"],  # Exclude system agents
            conditions=[{"type": "request_frequency", "max_requests_per_hour": 500}],
            decision=AccessDecision.CONDITIONAL,
            priority=100,
            created_by="setup_system",
        )
        self.access_control.add_policy(rate_limit_policy)
        policies_created += 1

        # Emergency lockdown policy (disabled by default)
        emergency_policy = AccessPolicy(
            policy_id="emergency_lockdown",
            name="Emergency System Lockdown",
            description="Emergency policy to deny all access except system admins",
            resource_types=set(ResourceType),
            actions=set(ActionType),
            agent_patterns=[r"^(?!system-admin-).*"],
            conditions=[],
            decision=AccessDecision.DENY,
            priority=1000,
            created_by="setup_system",
            is_active=False,  # Disabled by default
        )
        self.access_control.add_policy(emergency_policy)
        policies_created += 1

        self.setup_results["policies_created"] = policies_created
        logger.info(f"✅ Created {policies_created} default security policies")

    async def _register_trinitas_agents(self):
        """Register Trinitas core agents with appropriate credentials."""
        logger.info("👥 Registering Trinitas core agents...")

        trinitas_agents = [
            {
                "agent_id": "athena-conductor",
                "display_name": "Athena - Harmonious Conductor",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.ELEVATED,
                "description": "System orchestration and workflow automation",
            },
            {
                "agent_id": "artemis-optimizer",
                "display_name": "Artemis - Technical Perfectionist",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.ELEVATED,
                "description": "Performance optimization and quality assurance",
            },
            {
                "agent_id": "hestia-auditor",
                "display_name": "Hestia - Security Guardian",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.ADMIN,
                "description": "Security auditing and threat detection",
            },
            {
                "agent_id": "eris-coordinator",
                "display_name": "Eris - Tactical Coordinator",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.ELEVATED,
                "description": "Tactical planning and conflict resolution",
            },
            {
                "agent_id": "hera-strategist",
                "display_name": "Hera - Strategic Commander",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.ELEVATED,
                "description": "Strategic planning and architecture design",
            },
            {
                "agent_id": "muses-documenter",
                "display_name": "Muses - Knowledge Architect",
                "namespace": "trinitas",
                "access_level": AgentAccessLevel.STANDARD,
                "description": "Documentation and knowledge management",
            },
        ]

        registered_agents = []

        for agent_info in trinitas_agents:
            try:
                registration = await self.authenticator.register_agent(
                    agent_id=agent_info["agent_id"],
                    namespace=agent_info["namespace"],
                    access_level=agent_info["access_level"],
                )

                registered_agents.append(
                    {
                        "agent_id": registration["agent_id"],
                        "namespace": registration["namespace"],
                        "api_key": registration["api_key"],  # Store securely!
                        "access_level": agent_info["access_level"].value,
                    }
                )

                logger.info(f"✅ Registered {agent_info['agent_id']}")

            except Exception as e:
                logger.error(f"❌ Failed to register {agent_info['agent_id']}: {e}")
                # Continue with other agents

        self.setup_results["registered_agents"] = registered_agents
        logger.info(f"✅ Registered {len(registered_agents)} Trinitas agents")

    async def _validate_security_config(self):
        """Validate security configuration and settings."""
        logger.info("🔍 Validating security configuration...")

        validation_results = {}

        # Check key strength (from generated keys)
        secret_key = self.setup_results["secret_key"]
        encryption_key = self.setup_results["encryption_key"]

        validation_results["secret_key_length"] = len(secret_key)
        validation_results["encryption_key_length"] = len(encryption_key)

        # Validate key strength (minimum 64 characters for production)
        if len(secret_key) < 64:
            raise ValueError("Secret key too weak (minimum 64 characters)")
        if len(encryption_key) < 64:
            raise ValueError("Encryption key too weak (minimum 64 characters)")

        # Check security settings (from Pydantic Settings)
        auth_enabled = self.settings.auth_enabled
        validation_results["auth_enabled"] = auth_enabled

        if not auth_enabled and self.settings.environment == "production":
            logger.warning("⚠️ Authentication disabled in production environment!")

        # Test encryption
        test_data = {"test": "security validation", "timestamp": datetime.utcnow().isoformat()}
        encrypted = await self.encryption.encrypt_agent_data(
            test_data, "test", "validation-agent", DataClassification.INTERNAL
        )
        decrypted = await self.encryption.decrypt_agent_data(encrypted, "test", "validation-agent")

        if decrypted["test"] != "security validation":
            raise ValueError("Encryption validation failed")

        validation_results["encryption_test"] = "passed"

        # Check access control
        validation_results["total_policies"] = len(self.access_control.policies)

        self.setup_results["validation"] = validation_results
        logger.info("✅ Security configuration validated")

    async def _generate_config_files(self):
        """Generate configuration files with security settings."""
        logger.info("📄 Generating configuration files...")

        # Generate environment file with security variables
        env_content = f"""# TMWS Security Configuration
# Generated by Hestia Security Setup on {datetime.utcnow().isoformat()}

# Security Keys (KEEP THESE SECRET!)
TMWS_SECRET_KEY={self.setup_results["secret_key"]}
TMWS_ENCRYPTION_KEY={self.setup_results["encryption_key"]}

# Authentication Settings
TMWS_AUTH_ENABLED=true

# Rate Limiting
TMWS_RATE_LIMIT_REQUESTS={self.settings.rate_limit_requests}
TMWS_RATE_LIMIT_PERIOD={self.settings.rate_limit_period}

# Environment
TMWS_ENVIRONMENT=production
"""

        # Write to .env.security file
        env_file = Path(__file__).parent.parent / ".env.security"
        env_file.write_text(env_content)

        # Generate agent credentials file
        agents_content = "# Trinitas Agent Credentials\n"
        agents_content += "# Generated by Hestia Security Setup\n"
        agents_content += "# KEEP THIS FILE SECURE!\n\n"

        for agent in self.setup_results.get("registered_agents", []):
            agents_content += f"# {agent['agent_id']} ({agent['access_level']})\n"
            agents_content += (
                f"{agent['agent_id'].upper().replace('-', '_')}_API_KEY={agent['api_key']}\n\n"
            )

        agents_file = Path(__file__).parent.parent / ".agents.credentials"
        agents_file.write_text(agents_content)

        # Set restrictive permissions
        os.chmod(env_file, 0o600)  # Read/write for owner only
        os.chmod(agents_file, 0o600)

        self.setup_results["config_files"] = {
            "env_file": str(env_file),
            "agents_file": str(agents_file),
        }

        logger.info("✅ Configuration files generated")
        logger.warning("🔒 IMPORTANT: Secure the generated credential files!")


async def main():
    """Main setup function."""
    import argparse

    parser = argparse.ArgumentParser(description="TMWS Security Setup")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--validate-only", action="store_true", help="Only validate existing config"
    )

    args = parser.parse_args()

    setup = SecuritySetup(args.config)

    try:
        if args.validate_only:
            logger.info("Running validation only...")
            await setup._validate_security_config()
            logger.info("✅ Validation completed successfully")
        else:
            results = await setup.run_setup()

            print("\n" + "=" * 60)
            print("🔥 HESTIA SECURITY SETUP COMPLETE")
            print("=" * 60)
            print(f"Status: {results['status']}")
            print(f"Registered agents: {len(results.get('registered_agents', []))}")
            print(f"Security policies: {results.get('policies_created', 0)}")
            print(f"Validation: {results.get('validation', {}).get('encryption_test', 'unknown')}")

            print("\n🔒 SECURITY REMINDERS:")
            print("1. Store agent credentials securely")
            print("2. Set up proper firewall rules")
            print("3. Enable audit logging in production")
            print("4. Regularly rotate encryption keys")
            print("5. Monitor security logs for anomalies")

            print("\n📁 Configuration files:")
            for file_type, file_path in results.get("config_files", {}).items():
                print(f"   {file_type}: {file_path}")

    except Exception as e:
        logger.error(f"❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
