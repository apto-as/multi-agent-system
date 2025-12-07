"""Skill Service Package - Progressive Disclosure Skills System.

This package provides skill management with:
- Progressive Disclosure (3 layers: metadata, core instructions, full content)
- Access control (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
- Namespace isolation (P0-1 security pattern)
- Version management (auto-versioning)
- Content integrity (SHA256 hashing)

Main components:
- SkillService: Main service class (coordinator)
- SkillCRUDOperations: CRUD operations
- SkillSharingOperations: SHARED access control
- SkillActivationOperations: MCP tool lifecycle

Backward compatibility:
- `from src.services.skill_service import SkillService` works unchanged
"""

from .core import SkillService
from .skill_activation import SkillActivationOperations
from .skill_crud import SkillCRUDOperations
from .skill_sharing import SkillSharingOperations

__all__ = [
    # Main service class
    "SkillService",
    # Sub-services (for advanced usage)
    "SkillCRUDOperations",
    "SkillSharingOperations",
    "SkillActivationOperations",
]
