"""TMWS MCP Server Constants.

This module contains shared constants used across the MCP server package.
"""

from importlib.metadata import version as get_version

try:
    __version__ = get_version("tmws")
except Exception:
    __version__ = "2.4.0"  # Fallback


# Trinitas Agent Definitions for Auto-Registration (v2.4.0+)
TRINITAS_AGENTS = {
    "athena-conductor": {
        "display_name": "Athena (Harmonious Conductor)",
        "agent_type": "trinitas",
        "agent_subtype": "conductor",
        "capabilities": ["orchestration", "workflow", "coordination"],
    },
    "artemis-optimizer": {
        "display_name": "Artemis (Technical Perfectionist)",
        "agent_type": "trinitas",
        "agent_subtype": "optimizer",
        "capabilities": ["performance", "optimization", "technical_excellence"],
    },
    "hestia-auditor": {
        "display_name": "Hestia (Security Guardian)",
        "agent_type": "trinitas",
        "agent_subtype": "auditor",
        "capabilities": ["security", "audit", "risk_assessment"],
    },
    "eris-coordinator": {
        "display_name": "Eris (Tactical Coordinator)",
        "agent_type": "trinitas",
        "agent_subtype": "coordinator",
        "capabilities": ["tactical", "team_coordination", "conflict_resolution"],
    },
    "hera-strategist": {
        "display_name": "Hera (Strategic Commander)",
        "agent_type": "trinitas",
        "agent_subtype": "strategist",
        "capabilities": ["strategy", "planning", "architecture"],
    },
    "muses-documenter": {
        "display_name": "Muses (Knowledge Architect)",
        "agent_type": "trinitas",
        "agent_subtype": "documenter",
        "capabilities": ["documentation", "knowledge", "archival"],
    },
    # Support Layer Agents (v2.4.7+)
    "aphrodite-designer": {
        "display_name": "Aphrodite (UI/UX Designer)",
        "agent_type": "trinitas",
        "agent_subtype": "designer",
        "capabilities": ["design", "ui", "ux", "interface", "accessibility"],
    },
    "metis-developer": {
        "display_name": "Metis (Development Assistant)",
        "agent_type": "trinitas",
        "agent_subtype": "developer",
        "capabilities": ["implementation", "testing", "debugging", "refactoring"],
    },
    "aurora-researcher": {
        "display_name": "Aurora (Research Assistant)",
        "agent_type": "trinitas",
        "agent_subtype": "researcher",
        "capabilities": ["search", "research", "context", "retrieval", "synthesis"],
    },
}
