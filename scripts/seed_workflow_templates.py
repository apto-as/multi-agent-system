#!/usr/bin/env python3
"""
Seed data for TMWS Workflow Templates (Issue #60)

This script provides the initial 4 system templates for Trinitas workflow orchestration:
1. quick_fix (2-phase) - Fast bug fixes and urgent patches
2. security_audit (3-phase) - Comprehensive security analysis
3. full (4-phase) - Complete workflow for complex implementations
4. research (2-phase) - Knowledge discovery and analysis

Usage:
    python scripts/seed_workflow_templates.py

Author: Eris (Tactical Coordinator)
Date: 2025-12-11
"""

from datetime import datetime
from typing import Any

# ============================================================================
# SYSTEM TEMPLATE SEED DATA
# ============================================================================

SYSTEM_TEMPLATES: list[dict[str, Any]] = [
    # ========================================================================
    # Template 1: quick_fix (2-phase)
    # ========================================================================
    {
        "name": "quick_fix",
        "description": "Fast 2-phase workflow for urgent bug fixes and hotfixes. "
        "Optimized for speed with parallel analysis and minimal verification.",
        "workflow_type": "sequential",
        "status": "active",
        "is_system_template": True,
        "complexity": "low",
        "estimated_duration_minutes": 30,
        "tags": ["system", "quick", "bug-fix", "urgent", "2-phase"],
        "created_by": "system",
        "steps": [
            {
                "name": "analysis_and_fix",
                "description": "Parallel analysis and fix implementation",
                "phase": 1,
                "agents": ["artemis", "metis"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "analysis_fix",
                    "priority": "high",
                    "description": "Artemis leads technical analysis, Metis implements fix",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [
                        {"type": "tests_passed", "threshold": 1.0},
                        {"type": "no_regressions", "threshold": 1.0},
                    ],
                },
            },
            {
                "name": "verification",
                "description": "Security and quality verification",
                "phase": 2,
                "agents": ["hestia"],
                "execution_mode": "single",
                "action": {
                    "type": "task",
                    "task_type": "security_check",
                    "priority": "high",
                    "description": "Hestia performs rapid security scan",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [{"type": "security_approved", "threshold": 1.0}],
                },
            },
        ],
        "config": {
            "max_execution_time_minutes": 30,
            "retry_on_failure": True,
            "max_retries": 2,
            "notification_channels": ["slack", "email"],
            "abort_on_security_failure": True,
        },
        "trigger_patterns": [
            r"\b(fix|bug|urgent|hotfix|critical|patch)\b",
            r"\b(quick\s+fix|fast\s+fix|emergency)\b",
        ],
        "metadata_json": {
            "template_version": "1.0.0",
            "author": "eris",
            "use_cases": [
                "Critical production bugs",
                "Security hotfixes",
                "Urgent performance issues",
            ],
            "success_rate_target": 0.95,
        },
    },
    # ========================================================================
    # Template 2: security_audit (3-phase)
    # ========================================================================
    {
        "name": "security_audit",
        "description": "Comprehensive 3-phase security audit workflow. "
        "Includes vulnerability scanning, risk analysis, and detailed reporting.",
        "workflow_type": "sequential",
        "status": "active",
        "is_system_template": True,
        "complexity": "high",
        "estimated_duration_minutes": 240,
        "tags": ["system", "security", "audit", "3-phase", "compliance"],
        "created_by": "system",
        "steps": [
            {
                "name": "vulnerability_scan",
                "description": "Initial vulnerability detection and cataloging",
                "phase": 1,
                "agents": ["hestia"],
                "execution_mode": "single",
                "action": {
                    "type": "task",
                    "task_type": "vulnerability_scan",
                    "priority": "high",
                    "description": "Hestia scans codebase for security vulnerabilities",
                },
                "approval_gate": {
                    "required": True,
                    "type": "manual",
                    "conditions": [{"type": "scan_complete", "threshold": 1.0}],
                    "approvers": ["security_team"],
                },
            },
            {
                "name": "risk_analysis",
                "description": "Parallel risk assessment and impact analysis",
                "phase": 2,
                "agents": ["hestia", "artemis"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "risk_analysis",
                    "priority": "high",
                    "description": "Hestia analyzes security risks, Artemis assesses technical impact",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [
                        {"type": "risk_scored", "threshold": 1.0},
                        {"type": "impact_assessed", "threshold": 1.0},
                    ],
                },
            },
            {
                "name": "security_report",
                "description": "Generate comprehensive security audit report",
                "phase": 3,
                "agents": ["muses"],
                "execution_mode": "single",
                "action": {
                    "type": "task",
                    "task_type": "documentation",
                    "priority": "medium",
                    "description": "Muses creates detailed security report with findings",
                },
                "approval_gate": {
                    "required": True,
                    "type": "manual",
                    "conditions": [{"type": "report_reviewed", "threshold": 1.0}],
                    "approvers": ["security_team", "compliance_team"],
                },
            },
        ],
        "config": {
            "max_execution_time_minutes": 240,
            "retry_on_failure": False,
            "max_retries": 0,
            "notification_channels": ["email", "compliance_dashboard"],
            "generate_compliance_artifacts": True,
            "severity_threshold": "medium",
        },
        "trigger_patterns": [
            r"\b(security|audit|vulnerability|threat|risk)\b",
            r"\b(pen\s*test|penetration|compliance|hardening)\b",
        ],
        "metadata_json": {
            "template_version": "1.0.0",
            "author": "eris",
            "use_cases": [
                "Pre-release security audits",
                "Compliance verification",
                "Post-incident analysis",
            ],
            "compliance_frameworks": ["SOC2", "ISO27001", "NIST"],
            "success_rate_target": 1.0,
        },
    },
    # ========================================================================
    # Template 3: full (4-phase) - Default Trinitas Full Mode
    # ========================================================================
    {
        "name": "full",
        "description": "Complete 4-phase Trinitas Full Mode workflow. "
        "Strategic planning, implementation, verification, and documentation. "
        "This is the default template for complex, high-value work.",
        "workflow_type": "sequential",
        "status": "active",
        "is_system_template": True,
        "complexity": "high",
        "estimated_duration_minutes": 480,
        "tags": [
            "system",
            "full-mode",
            "4-phase",
            "strategic",
            "comprehensive",
            "default",
        ],
        "created_by": "system",
        "steps": [
            {
                "name": "strategic_planning",
                "description": "Strategic analysis and resource coordination",
                "phase": 1,
                "agents": ["hera", "athena"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "strategic_planning",
                    "priority": "high",
                    "description": "Hera designs strategy and architecture, Athena coordinates resources",
                },
                "approval_gate": {
                    "required": True,
                    "type": "consensus",
                    "conditions": [
                        {"type": "both_agents_approve", "agents": ["hera", "athena"]},
                        {"type": "architecture_validated", "threshold": 0.9},
                    ],
                    "approvers": ["hera", "athena"],
                },
            },
            {
                "name": "implementation",
                "description": "Technical implementation and testing",
                "phase": 2,
                "agents": ["artemis", "metis"],
                "execution_mode": "sequential",
                "action": {
                    "type": "task",
                    "task_type": "implementation",
                    "priority": "high",
                    "description": "Artemis leads implementation, Metis creates tests",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [
                        {"type": "tests_passed", "threshold": 1.0},
                        {"type": "no_regressions", "threshold": 1.0},
                        {"type": "code_quality", "threshold": 0.9},
                    ],
                },
            },
            {
                "name": "verification",
                "description": "Security audit and context verification",
                "phase": 3,
                "agents": ["hestia", "aurora"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "verification",
                    "priority": "high",
                    "description": "Hestia audits security, Aurora verifies context integrity",
                },
                "approval_gate": {
                    "required": True,
                    "type": "consensus",
                    "conditions": [
                        {"type": "security_approved", "threshold": 1.0},
                        {"type": "context_validated", "threshold": 0.95},
                    ],
                    "approvers": ["hestia"],
                },
            },
            {
                "name": "documentation",
                "description": "Comprehensive documentation and design guidelines",
                "phase": 4,
                "agents": ["muses", "aphrodite"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "documentation",
                    "priority": "medium",
                    "description": "Muses creates docs, Aphrodite provides UI/UX guidelines",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [{"type": "documentation_complete", "threshold": 1.0}],
                },
            },
        ],
        "config": {
            "max_execution_time_minutes": 480,
            "retry_on_failure": True,
            "max_retries": 1,
            "notification_channels": ["slack", "email", "dashboard"],
            "enable_memory_recording": True,
            "trust_score_tracking": True,
            "abort_on_security_failure": True,
        },
        "trigger_patterns": [
            r"\b(trinitas\s+full\s+mode|full\s+mode|フルモード)\b",
            r"\b(implement|develop|architecture|strategic)\b",
            r"\b(complex|comprehensive|end-to-end)\b",
        ],
        "metadata_json": {
            "template_version": "1.0.0",
            "author": "eris",
            "use_cases": [
                "Major feature implementations",
                "Architecture redesigns",
                "Complex multi-system integrations",
            ],
            "is_default": True,
            "success_rate_target": 0.98,
        },
    },
    # ========================================================================
    # Template 4: research (2-phase)
    # ========================================================================
    {
        "name": "research",
        "description": "Focused 2-phase research workflow for knowledge discovery and analysis. "
        "Combines semantic search with strategic synthesis.",
        "workflow_type": "sequential",
        "status": "active",
        "is_system_template": True,
        "complexity": "medium",
        "estimated_duration_minutes": 120,
        "tags": ["system", "research", "analysis", "2-phase", "knowledge"],
        "created_by": "system",
        "steps": [
            {
                "name": "knowledge_search",
                "description": "Parallel knowledge discovery and documentation search",
                "phase": 1,
                "agents": ["aurora", "muses"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "research",
                    "priority": "medium",
                    "description": "Aurora performs semantic search, Muses retrieves documentation",
                },
                "approval_gate": {
                    "required": True,
                    "type": "automatic",
                    "conditions": [
                        {"type": "results_found", "threshold": 0.8},
                        {"type": "relevance_score", "threshold": 0.7},
                    ],
                },
            },
            {
                "name": "analysis_and_synthesis",
                "description": "Strategic analysis and knowledge synthesis",
                "phase": 2,
                "agents": ["hera", "athena"],
                "execution_mode": "parallel",
                "action": {
                    "type": "task",
                    "task_type": "analysis",
                    "priority": "medium",
                    "description": "Hera provides strategic insights, Athena synthesizes findings",
                },
                "approval_gate": {
                    "required": True,
                    "type": "consensus",
                    "conditions": [
                        {"type": "synthesis_complete", "threshold": 0.9},
                        {"type": "insights_generated", "threshold": 0.85},
                    ],
                    "approvers": ["hera", "athena"],
                },
            },
        ],
        "config": {
            "max_execution_time_minutes": 120,
            "retry_on_failure": True,
            "max_retries": 1,
            "notification_channels": ["slack"],
            "enable_memory_recording": True,
            "semantic_search_depth": "deep",
        },
        "trigger_patterns": [
            r"\b(research|analyze|investigate|explore|discover)\b",
            r"\b(study|survey|review|examine)\b",
        ],
        "metadata_json": {
            "template_version": "1.0.0",
            "author": "eris",
            "use_cases": [
                "Technical feasibility studies",
                "Architecture decision research",
                "Best practices investigation",
            ],
            "success_rate_target": 0.92,
        },
    },
]


# ============================================================================
# TEMPLATE METADATA
# ============================================================================

TEMPLATE_METADATA = {
    "seed_version": "1.0.0",
    "seed_date": datetime.utcnow().isoformat(),
    "total_templates": len(SYSTEM_TEMPLATES),
    "template_names": [t["name"] for t in SYSTEM_TEMPLATES],
    "complexity_distribution": {
        "low": 1,  # quick_fix
        "medium": 1,  # research
        "high": 2,  # security_audit, full
    },
    "phase_distribution": {
        "2-phase": 2,  # quick_fix, research
        "3-phase": 1,  # security_audit
        "4-phase": 1,  # full
    },
    "author": "eris",
    "protocol_version": "2.4.16",
}


# ============================================================================
# SEEDING FUNCTIONS
# ============================================================================


async def seed_templates_to_database(session):
    """
    Seed templates to database using WorkflowService.

    Args:
        session: AsyncSession for database operations

    Returns:
        list[Workflow]: Created workflow templates
    """
    from src.services.workflow_service import WorkflowService

    workflow_service = WorkflowService(session)
    created_templates = []

    for template_data in SYSTEM_TEMPLATES:
        try:
            # Extract workflow-specific fields
            workflow = await workflow_service.create_workflow(
                name=template_data["name"],
                description=template_data["description"],
                steps=template_data["steps"],
                workflow_type=template_data["workflow_type"],
                metadata=template_data.get("metadata_json", {}),
            )

            # Update additional fields
            workflow.status = template_data["status"]
            workflow.tags = template_data.get("tags", [])
            workflow.config = template_data.get("config", {})
            workflow.created_by = template_data.get("created_by", "system")

            await session.commit()
            await session.refresh(workflow)

            created_templates.append(workflow)

            print(f"✅ Created template: {workflow.name}")

        except Exception as e:
            print(f"❌ Failed to create template {template_data['name']}: {e}")
            await session.rollback()

    return created_templates


def get_template_by_name(name: str) -> dict[str, Any] | None:
    """
    Get template seed data by name.

    Args:
        name: Template name (e.g., "quick_fix", "full")

    Returns:
        Template dictionary or None if not found
    """
    for template in SYSTEM_TEMPLATES:
        if template["name"] == name:
            return template
    return None


def list_template_names() -> list[str]:
    """Get list of all template names."""
    return [t["name"] for t in SYSTEM_TEMPLATES]


def get_templates_by_complexity(complexity: str) -> list[dict[str, Any]]:
    """
    Get templates filtered by complexity level.

    Args:
        complexity: "low", "medium", or "high"

    Returns:
        List of matching templates
    """
    return [t for t in SYSTEM_TEMPLATES if t.get("complexity") == complexity]


def get_templates_by_phase_count(phase_count: int) -> list[dict[str, Any]]:
    """
    Get templates by number of phases.

    Args:
        phase_count: Number of phases (2, 3, or 4)

    Returns:
        List of matching templates
    """
    return [t for t in SYSTEM_TEMPLATES if len(t["steps"]) == phase_count]


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    import asyncio

    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker

    async def main():
        """Main seeding function."""
        # Create database connection
        # Note: Update DATABASE_URL for your environment
        DATABASE_URL = "sqlite+aiosqlite:///./tmws.db"

        engine = create_async_engine(DATABASE_URL, echo=True)
        async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with async_session_maker() as session:
            print("🚀 Starting template seeding...")
            print(f"📊 Seeding {len(SYSTEM_TEMPLATES)} system templates")

            created = await seed_templates_to_database(session)

            print(f"\n✅ Successfully seeded {len(created)} templates")
            print("\n📋 Template Summary:")
            for template in created:
                print(f"  - {template.name} ({template.workflow_type}, {len(template.steps)} phases)")

            print("\n✅ Seeding complete!")

    # Run seeding
    asyncio.run(main())
