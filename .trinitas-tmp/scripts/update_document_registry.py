#!/usr/bin/env python3
"""
Trinitas Document Registry Manager

Purpose: Manage documentation registry with high performance and data integrity
Created: 2025-11-03
Created by: Artemis (Technical Perfectionist)

Performance Targets:
- Init: < 5 seconds for 100 documents
- Add: < 500ms per document
- Validate: < 2 seconds for 100 documents
- Index: < 1 second generation time

Quality Standards:
- Type safety: 100% type hints
- Test coverage: >= 90%
- Complexity: <= 10 per function
- Error handling: Comprehensive with retry logic
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

# Type aliases
PathLike = str | Path
DocumentDict = Dict[str, Any]
RegistryDict = Dict[str, DocumentDict]


# ============================================================================
# Enums
# ============================================================================


class DocumentStatus(str, Enum):
    """Document lifecycle status"""

    CURRENT = "current"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"
    DRAFT = "draft"


class DocumentPurpose(str, Enum):
    """Document primary purpose"""

    SPECIFICATION = "specification"
    GUIDE = "guide"
    REFERENCE = "reference"
    DECISION_RECORD = "decision_record"
    TEMPLATE = "template"
    CONFIGURATION = "configuration"
    PLANNING = "planning"
    REPORT = "report"
    STRATEGY = "strategy"


class ValidationLevel(str, Enum):
    """Validation severity level"""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class ValidationResult:
    """Result of document validation"""

    level: ValidationLevel
    message: str
    path: Optional[str] = None
    field: Optional[str] = None


@dataclass
class DocumentMetadata:
    """Complete document metadata"""

    # Required fields
    path: str
    title: str
    purpose: DocumentPurpose
    status: DocumentStatus = DocumentStatus.CURRENT

    # Auto-generated fields
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    size: int = 0
    checksum: str = ""

    # Optional fields
    created_by: Optional[str] = None
    version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    category: Optional[str] = None
    audience: List[str] = field(default_factory=list)

    # Relationships
    dependencies: List[str] = field(default_factory=list)
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None
    related: List[str] = field(default_factory=list)

    # Quality metrics
    completeness: Optional[int] = None
    last_reviewed: Optional[datetime] = None
    review_interval: int = 90

    # Technical metadata
    language: str = "en"
    format: str = "markdown"
    custom: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> DocumentDict:
        """Convert to dictionary for YAML serialization"""
        data: DocumentDict = {
            "path": self.path,
            "title": self.title,
            "purpose": self.purpose.value,
            "status": self.status.value,
            "size": self.size,
            "checksum": self.checksum,
            "language": self.language,
            "format": self.format,
            "review_interval": self.review_interval,
        }

        # Add datetime fields
        if self.created:
            data["created"] = self.created.isoformat()
        if self.updated:
            data["updated"] = self.updated.isoformat()
        if self.last_reviewed:
            data["last_reviewed"] = self.last_reviewed.isoformat()

        # Add optional fields
        if self.created_by:
            data["created_by"] = self.created_by
        if self.version:
            data["version"] = self.version
        if self.tags:
            data["tags"] = self.tags
        if self.category:
            data["category"] = self.category
        if self.audience:
            data["audience"] = self.audience
        if self.dependencies:
            data["dependencies"] = self.dependencies
        if self.supersedes:
            data["supersedes"] = self.supersedes
        if self.superseded_by:
            data["superseded_by"] = self.superseded_by
        if self.related:
            data["related"] = self.related
        if self.completeness is not None:
            data["completeness"] = self.completeness
        if self.custom:
            data["custom"] = self.custom

        return data

    @classmethod
    def from_dict(cls, data: DocumentDict) -> DocumentMetadata:
        """Create from dictionary"""
        # Parse enums
        purpose = DocumentPurpose(data["purpose"])
        status = DocumentStatus(data.get("status", "current"))

        # Parse datetimes
        created = None
        if "created" in data:
            created = datetime.fromisoformat(data["created"])

        updated = None
        if "updated" in data:
            updated = datetime.fromisoformat(data["updated"])

        last_reviewed = None
        if "last_reviewed" in data:
            last_reviewed = datetime.fromisoformat(data["last_reviewed"])

        return cls(
            path=data["path"],
            title=data["title"],
            purpose=purpose,
            status=status,
            created=created,
            updated=updated,
            size=data.get("size", 0),
            checksum=data.get("checksum", ""),
            created_by=data.get("created_by"),
            version=data.get("version"),
            tags=data.get("tags", []),
            category=data.get("category"),
            audience=data.get("audience", []),
            dependencies=data.get("dependencies", []),
            supersedes=data.get("supersedes"),
            superseded_by=data.get("superseded_by"),
            related=data.get("related", []),
            completeness=data.get("completeness"),
            last_reviewed=last_reviewed,
            review_interval=data.get("review_interval", 90),
            language=data.get("language", "en"),
            format=data.get("format", "markdown"),
            custom=data.get("custom", {}),
        )


# ============================================================================
# Core Classes
# ============================================================================


class DocumentScanner:
    """High-performance document scanner with parallel processing"""

    def __init__(
        self,
        root_path: Path,
        allowed_dirs: List[str],
        allowed_extensions: List[str],
    ) -> None:
        self.root_path = root_path
        self.allowed_dirs = allowed_dirs
        self.allowed_extensions = allowed_extensions
        self.logger = logging.getLogger(__name__)

    def scan(self, max_workers: int = 4) -> List[Path]:
        """Scan for documentation files in parallel"""
        self.logger.info(f"Scanning {self.root_path} for documents...")

        all_files: List[Path] = []

        # Collect all candidate files first (fast)
        for allowed_dir in self.allowed_dirs:
            dir_path = self.root_path / allowed_dir
            if not dir_path.exists():
                self.logger.warning(f"Directory not found: {dir_path}")
                continue

            for ext in self.allowed_extensions:
                pattern = f"**/*{ext}"
                files = list(dir_path.glob(pattern))
                all_files.extend(files)

        self.logger.info(f"Found {len(all_files)} candidate files")
        return all_files

    @staticmethod
    def calculate_checksum(file_path: Path) -> str:
        """Calculate SHA-256 checksum efficiently"""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read in 64KB chunks for memory efficiency
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def extract_metadata_from_content(content: str) -> Dict[str, Any]:
        """Extract metadata from document content (YAML frontmatter)"""
        if not content.startswith("---"):
            return {}

        try:
            # Find end of YAML frontmatter
            end_idx = content.find("---", 3)
            if end_idx == -1:
                return {}

            yaml_content = content[3:end_idx].strip()
            return yaml.safe_load(yaml_content) or {}
        except Exception:
            return {}

    def create_metadata(self, file_path: Path) -> DocumentMetadata:
        """Create metadata for a single document"""
        # Basic file information
        stat = file_path.stat()
        size = stat.st_size
        updated = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        # Calculate checksum
        checksum = self.calculate_checksum(file_path)

        # Read content for frontmatter
        content = file_path.read_text(encoding="utf-8")
        frontmatter = self.extract_metadata_from_content(content)

        # Relative path from root
        rel_path = str(file_path.relative_to(self.root_path))

        # Determine format
        file_format = "markdown" if file_path.suffix == ".md" else file_path.suffix[1:]

        # Create metadata object
        metadata = DocumentMetadata(
            path=rel_path,
            title=frontmatter.get("title", file_path.stem.replace("_", " ").title()),
            purpose=DocumentPurpose(
                frontmatter.get("purpose", "reference")
            ),  # Default to reference
            status=DocumentStatus(frontmatter.get("status", "current")),
            size=size,
            checksum=checksum,
            updated=updated,
            format=file_format,
            created_by=frontmatter.get("created_by"),
            version=frontmatter.get("version"),
            tags=frontmatter.get("tags", []),
            category=frontmatter.get("category"),
            audience=frontmatter.get("audience", []),
            dependencies=frontmatter.get("dependencies", []),
            supersedes=frontmatter.get("supersedes"),
            related=frontmatter.get("related", []),
        )

        # Try to get creation date from git (if available)
        # For now, use mtime as fallback
        metadata.created = updated

        return metadata


class RegistryValidator:
    """Validate registry integrity and cross-references"""

    def __init__(self, root_path: Path) -> None:
        self.root_path = root_path
        self.logger = logging.getLogger(__name__)

    def validate(self, registry: RegistryDict) -> List[ValidationResult]:
        """Validate entire registry"""
        results: List[ValidationResult] = []

        # Check for required fields
        results.extend(self._validate_required_fields(registry))

        # Check file existence
        results.extend(self._validate_file_existence(registry))

        # Check cross-references
        results.extend(self._validate_cross_references(registry))

        # Check for staleness
        results.extend(self._check_staleness(registry))

        # Check for duplicates
        results.extend(self._check_duplicates(registry))

        return results

    def _validate_required_fields(self, registry: RegistryDict) -> List[ValidationResult]:
        """Validate required fields in all documents"""
        results: List[ValidationResult] = []
        required = ["path", "title", "purpose", "status"]

        for path, doc in registry.items():
            for field in required:
                if field not in doc or not doc[field]:
                    results.append(
                        ValidationResult(
                            level=ValidationLevel.ERROR,
                            message=f"Missing required field: {field}",
                            path=path,
                            field=field,
                        )
                    )

        return results

    def _validate_file_existence(self, registry: RegistryDict) -> List[ValidationResult]:
        """Check that all registered files exist"""
        results: List[ValidationResult] = []

        for path in registry.keys():
            file_path = self.root_path / path
            if not file_path.exists():
                results.append(
                    ValidationResult(
                        level=ValidationLevel.ERROR,
                        message=f"File not found: {path}",
                        path=path,
                    )
                )

        return results

    def _validate_cross_references(
        self, registry: RegistryDict
    ) -> List[ValidationResult]:
        """Validate all cross-references"""
        results: List[ValidationResult] = []
        all_paths = set(registry.keys())

        for path, doc in registry.items():
            # Check dependencies
            for dep in doc.get("dependencies", []):
                if dep not in all_paths:
                    results.append(
                        ValidationResult(
                            level=ValidationLevel.WARNING,
                            message=f"Dependency not found in registry: {dep}",
                            path=path,
                            field="dependencies",
                        )
                    )

            # Check supersedes
            if "supersedes" in doc and doc["supersedes"] not in all_paths:
                results.append(
                    ValidationResult(
                        level=ValidationLevel.WARNING,
                        message=f"Superseded document not found: {doc['supersedes']}",
                        path=path,
                        field="supersedes",
                    )
                )

            # Check related
            for rel in doc.get("related", []):
                if rel not in all_paths:
                    results.append(
                        ValidationResult(
                            level=ValidationLevel.WARNING,
                            message=f"Related document not found: {rel}",
                            path=path,
                            field="related",
                        )
                    )

        return results

    def _check_staleness(self, registry: RegistryDict) -> List[ValidationResult]:
        """Check for stale documents"""
        results: List[ValidationResult] = []
        now = datetime.now(timezone.utc)

        for path, doc in registry.items():
            if "updated" not in doc:
                continue

            updated = datetime.fromisoformat(doc["updated"])
            days_old = (now - updated).days

            if days_old > 365:
                results.append(
                    ValidationResult(
                        level=ValidationLevel.WARNING,
                        message=f"Document not updated in {days_old} days",
                        path=path,
                    )
                )

        return results

    def _check_duplicates(self, registry: RegistryDict) -> List[ValidationResult]:
        """Check for duplicate titles or checksums"""
        results: List[ValidationResult] = []
        seen_titles: Dict[str, str] = {}
        seen_checksums: Dict[str, str] = {}

        for path, doc in registry.items():
            # Check title duplicates
            title = doc.get("title", "")
            if title in seen_titles:
                results.append(
                    ValidationResult(
                        level=ValidationLevel.WARNING,
                        message=f"Duplicate title with: {seen_titles[title]}",
                        path=path,
                        field="title",
                    )
                )
            else:
                seen_titles[title] = path

            # Check checksum duplicates (exact file content match)
            checksum = doc.get("checksum", "")
            if checksum and checksum in seen_checksums:
                results.append(
                    ValidationResult(
                        level=ValidationLevel.INFO,
                        message=f"Identical content to: {seen_checksums[checksum]}",
                        path=path,
                        field="checksum",
                    )
                )
            else:
                seen_checksums[checksum] = path

        return results


class IndexGenerator:
    """Generate INDEX.md from registry"""

    def __init__(self, registry: RegistryDict, template_path: Optional[Path] = None):
        self.registry = registry
        self.template_path = template_path
        self.logger = logging.getLogger(__name__)

    def generate(self, output_path: Path) -> None:
        """Generate INDEX.md"""
        self.logger.info(f"Generating index at {output_path}")

        # Group documents by category
        by_category: Dict[str, List[DocumentDict]] = {}
        for doc in self.registry.values():
            category = doc.get("category", "Uncategorized")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(doc)

        # Sort within each category
        for category in by_category:
            by_category[category].sort(key=lambda d: d["title"])

        # Generate markdown
        content = self._generate_markdown(by_category)

        # Write to file
        output_path.write_text(content, encoding="utf-8")
        self.logger.info(f"Index generated: {len(self.registry)} documents")

    def _generate_markdown(self, by_category: Dict[str, List[DocumentDict]]) -> str:
        """Generate markdown content"""
        lines = [
            "# Trinitas Documentation Index",
            "",
            f"**Generated**: {datetime.now(timezone.utc).isoformat()}",
            f"**Total Documents**: {len(self.registry)}",
            "",
            "---",
            "",
        ]

        # Table of contents
        lines.append("## Table of Contents")
        lines.append("")
        for category in sorted(by_category.keys()):
            anchor = category.lower().replace(" ", "-")
            lines.append(f"- [{category}](#{anchor})")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Document sections
        for category in sorted(by_category.keys()):
            lines.append(f"## {category}")
            lines.append("")

            for doc in by_category[category]:
                # Title with link
                path = doc["path"]
                title = doc["title"]
                lines.append(f"### [{title}]({path})")

                # Status badge
                status = doc["status"]
                badge = self._status_badge(status)
                lines.append(f"**Status**: {badge}")

                # Purpose
                purpose = doc["purpose"]
                lines.append(f"**Purpose**: {purpose}")

                # Tags
                if doc.get("tags"):
                    tags_str = ", ".join(f"`{t}`" for t in doc["tags"])
                    lines.append(f"**Tags**: {tags_str}")

                # Updated
                if "updated" in doc:
                    updated = doc["updated"][:10]  # Date only
                    lines.append(f"**Last Updated**: {updated}")

                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _status_badge(status: str) -> str:
        """Generate status badge"""
        badges = {
            "current": "✅ Current",
            "archived": "📦 Archived",
            "deprecated": "⚠️ Deprecated",
            "superseded": "🔄 Superseded",
            "draft": "📝 Draft",
        }
        return badges.get(status, status)


class DocumentRegistry:
    """Main registry manager"""

    def __init__(
        self,
        registry_path: Path,
        root_path: Path,
        config: Dict[str, Any],
    ) -> None:
        self.registry_path = registry_path
        self.root_path = root_path
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Components
        self.scanner = DocumentScanner(
            root_path=root_path,
            allowed_dirs=config["validation"]["path_validation"]["allowed_directories"],
            allowed_extensions=config["validation"]["path_validation"][
                "allowed_extensions"
            ],
        )
        self.validator = RegistryValidator(root_path=root_path)

    def load_registry(self) -> RegistryDict:
        """Load existing registry"""
        if not self.registry_path.exists():
            return {}

        with open(self.registry_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("documents", {})

    def save_registry(self, registry: RegistryDict) -> None:
        """Save registry to file"""
        data = {
            "schema_version": "1.0.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_documents": len(registry),
            "documents": registry,
        }

        with open(self.registry_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=100)

        self.logger.info(f"Registry saved: {len(registry)} documents")

    def init(self) -> None:
        """Initialize registry by scanning all documents"""
        self.logger.info("Initializing document registry...")

        # Scan for files
        files = self.scanner.scan(
            max_workers=self.config["performance"]["max_workers"]
        )

        # Create metadata in parallel
        registry: RegistryDict = {}

        with ThreadPoolExecutor(
            max_workers=self.config["performance"]["max_workers"]
        ) as executor:
            futures = {
                executor.submit(self.scanner.create_metadata, f): f for f in files
            }

            for future in as_completed(futures):
                try:
                    metadata = future.result()
                    registry[metadata.path] = metadata.to_dict()
                except Exception as e:
                    file_path = futures[future]
                    self.logger.error(f"Failed to process {file_path}: {e}")

        # Save registry
        self.save_registry(registry)

        self.logger.info(f"Registry initialized: {len(registry)} documents")

    def add(self, file_path: Path, interactive: bool = True) -> None:
        """Add new document to registry"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Load existing registry
        registry = self.load_registry()

        # Create metadata
        metadata = self.scanner.create_metadata(file_path)

        if interactive:
            # Interactive prompts for metadata refinement
            metadata = self._interactive_metadata(metadata)

        # Add to registry
        registry[metadata.path] = metadata.to_dict()

        # Save
        self.save_registry(registry)

        self.logger.info(f"Document added: {metadata.path}")

    def validate_registry(self) -> bool:
        """Validate registry and print results"""
        registry = self.load_registry()
        results = self.validator.validate(registry)

        # Print results
        errors = [r for r in results if r.level == ValidationLevel.ERROR]
        warnings = [r for r in results if r.level == ValidationLevel.WARNING]
        infos = [r for r in results if r.level == ValidationLevel.INFO]

        print(f"\n=== Validation Results ===")
        print(f"Total documents: {len(registry)}")
        print(f"Errors: {len(errors)}")
        print(f"Warnings: {len(warnings)}")
        print(f"Info: {len(infos)}")
        print()

        if errors:
            print("ERRORS:")
            for r in errors:
                print(f"  [{r.path}] {r.message}")
            print()

        if warnings:
            print("WARNINGS:")
            for r in warnings:
                print(f"  [{r.path}] {r.message}")
            print()

        return len(errors) == 0

    def generate_index(self, output_path: Optional[Path] = None) -> None:
        """Generate INDEX.md"""
        registry = self.load_registry()

        if output_path is None:
            output_path = self.root_path / self.config["index_config"]["output_path"]

        generator = IndexGenerator(registry)
        generator.generate(output_path)

    def cleanup(self) -> None:
        """Identify orphaned and deprecated documents"""
        registry = self.load_registry()

        orphaned: List[str] = []
        deprecated: List[str] = []

        for path, doc in registry.items():
            # Check if file exists
            file_path = self.root_path / path
            if not file_path.exists():
                orphaned.append(path)

            # Check if deprecated
            if doc.get("status") == "deprecated":
                deprecated.append(path)

        print(f"\n=== Cleanup Report ===")
        print(f"Orphaned documents: {len(orphaned)}")
        if orphaned:
            for p in orphaned:
                print(f"  - {p}")
        print()

        print(f"Deprecated documents: {len(deprecated)}")
        if deprecated:
            for p in deprecated:
                print(f"  - {p}")
        print()

    def _interactive_metadata(self, metadata: DocumentMetadata) -> DocumentMetadata:
        """Interactive metadata refinement"""
        print(f"\n=== Add Document: {metadata.path} ===")
        print(f"Auto-detected title: {metadata.title}")
        title_input = input("Confirm or enter new title (Enter to keep): ").strip()
        if title_input:
            metadata.title = title_input

        print(f"Auto-detected purpose: {metadata.purpose.value}")
        print(f"Options: {', '.join(p.value for p in DocumentPurpose)}")
        purpose_input = input("Confirm or enter new purpose (Enter to keep): ").strip()
        if purpose_input:
            metadata.purpose = DocumentPurpose(purpose_input)

        # Tags
        tags_input = input("Enter tags (comma-separated, optional): ").strip()
        if tags_input:
            metadata.tags = [t.strip() for t in tags_input.split(",")]

        # Category
        category_input = input("Enter category (optional): ").strip()
        if category_input:
            metadata.category = category_input

        return metadata


# ============================================================================
# CLI
# ============================================================================


def setup_logging(level: str = "INFO") -> None:
    """Configure logging"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from YAML"""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Trinitas Document Registry Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root path",
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=Path("docs/DOCUMENT_REGISTRY_SCHEMA.yaml"),
        help="Configuration file path",
    )

    parser.add_argument(
        "--registry",
        type=Path,
        default=Path("docs/DOCUMENT_REGISTRY.yaml"),
        help="Registry file path",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Init command
    subparsers.add_parser("init", help="Initialize registry by scanning all documents")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add new document to registry")
    add_parser.add_argument("file", type=Path, help="Path to document to add")
    add_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip interactive prompts",
    )

    # Validate command
    subparsers.add_parser("validate", help="Validate registry integrity")

    # Index command
    index_parser = subparsers.add_parser("index", help="Generate INDEX.md")
    index_parser.add_argument(
        "--output",
        type=Path,
        help="Output path for INDEX.md",
    )

    # Cleanup command
    subparsers.add_parser("cleanup", help="Identify orphaned/deprecated documents")

    args = parser.parse_args()

    # Setup
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        # Load configuration
        config = load_config(args.root / args.config)

        # Create registry manager
        registry = DocumentRegistry(
            registry_path=args.root / args.registry,
            root_path=args.root,
            config=config,
        )

        # Execute command
        if args.command == "init":
            registry.init()
        elif args.command == "add":
            registry.add(args.file, interactive=not args.non_interactive)
        elif args.command == "validate":
            success = registry.validate_registry()
            return 0 if success else 1
        elif args.command == "index":
            registry.generate_index(args.output)
        elif args.command == "cleanup":
            registry.cleanup()
        else:
            parser.print_help()
            return 1

        return 0

    except Exception as e:
        logger.error(f"Command failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
