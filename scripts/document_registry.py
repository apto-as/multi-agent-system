#!/usr/bin/env python3
"""
Trinitas Document Registry System - MVP v1.0
============================================

Secure document metadata management for Trinitas-agents project.

Security Compliance:
- CRIT-01: Path traversal prevention (CWE-22)
- CRIT-02: Symlink protection (CWE-61)
- CRIT-03: File size limits (CWE-400)
- CRIT-04: Safe JSON handling
- CRIT-05: Basic race condition protection

Author: Trinitas Full Mode (Athena, Artemis, Hestia, Eris, Hera, Muses)
Date: 2025-11-03
License: MIT
"""

import json
import hashlib
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import argparse
import fcntl
import re


# ============================================================================
# Security Configuration
# ============================================================================

class SecurityConfig:
    """Security limits and validation rules"""
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB (CRIT-03)
    MAX_METADATA_SIZE = 1024 * 1024   # 1MB
    MAX_PATH_LENGTH = 512
    MAX_TITLE_LENGTH = 200
    MAX_TAGS = 20
    MAX_TAG_LENGTH = 50

    ALLOWED_EXTENSIONS = {'.md', '.markdown', '.txt', '.yaml', '.json'}
    FORBIDDEN_PATTERNS = ['..', '~', '${', '$(', '\x00']

    # Allowed directories (relative to project root)
    ALLOWED_DIRS = ['docs/', 'trinitas_sources/']


# ============================================================================
# Security Utilities
# ============================================================================

class SecurityError(Exception):
    """Security validation error"""
    def __init__(self, message: str, code: str = "SEC"):
        super().__init__(message)
        self.code = code


def validate_path(path: Path, base_dir: Path) -> Path:
    """
    Validate file path against security threats

    Protects against:
    - Path traversal (CWE-22)
    - Symlinks (CWE-61)
    - Invalid extensions

    Args:
        path: Path to validate
        base_dir: Base directory to restrict access

    Returns:
        Resolved absolute path

    Raises:
        SecurityError: If path is invalid or dangerous
    """
    # Convert to string for pattern checking
    path_str = str(path)

    # Check forbidden patterns (CRIT-01)
    for pattern in SecurityConfig.FORBIDDEN_PATTERNS:
        if pattern in path_str:
            raise SecurityError(
                f"Path contains forbidden pattern '{pattern}': {path}",
                code="CWE-22"
            )

    # Check path length
    if len(path_str) > SecurityConfig.MAX_PATH_LENGTH:
        raise SecurityError(
            f"Path too long: {len(path_str)} (max: {SecurityConfig.MAX_PATH_LENGTH})",
            code="PATH-LEN"
        )

    # Resolve to absolute path
    try:
        resolved = path.resolve(strict=False)
    except (ValueError, OSError) as e:
        raise SecurityError(f"Invalid path: {path} ({e})", code="CWE-22")

    # Check if path is symlink (CRIT-02)
    if resolved.exists() and resolved.is_symlink():
        raise SecurityError(
            f"Symlink access denied (CWE-61): {path}",
            code="CWE-61"
        )

    # Ensure path is within base directory
    base_resolved = base_dir.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError:
        raise SecurityError(
            f"Path outside base directory: {path}\n"
            f"Resolved: {resolved}\n"
            f"Base: {base_resolved}",
            code="CWE-22"
        )

    # Check file extension
    if resolved.suffix not in SecurityConfig.ALLOWED_EXTENSIONS:
        raise SecurityError(
            f"Invalid file extension: {resolved.suffix}",
            code="EXT"
        )

    return resolved


def check_file_size(path: Path) -> int:
    """
    Check file size against limit (CRIT-03)

    Args:
        path: File to check

    Returns:
        File size in bytes

    Raises:
        SecurityError: If file exceeds size limit
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    size = path.stat().st_size

    if size > SecurityConfig.MAX_FILE_SIZE:
        raise SecurityError(
            f"File too large: {size} bytes (max: {SecurityConfig.MAX_FILE_SIZE})",
            code="CWE-400"
        )

    return size


def calculate_checksum(path: Path) -> str:
    """
    Calculate SHA-256 checksum of file

    Args:
        path: File to checksum

    Returns:
        Hex-encoded SHA-256 checksum
    """
    sha256 = hashlib.sha256()

    with open(path, 'rb') as f:
        # Read in 64KB chunks
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)

    return sha256.hexdigest()


def sanitize_string(s: str, max_length: int) -> str:
    """
    Sanitize user input string

    Args:
        s: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    # Remove control characters
    s = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', s)

    # Truncate to max length
    if len(s) > max_length:
        s = s[:max_length]

    return s.strip()


# ============================================================================
# Data Models
# ============================================================================

class DocumentStatus(Enum):
    """Document lifecycle status"""
    CURRENT = "current"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"


class DocumentPurpose(Enum):
    """Document purpose/type"""
    GUIDE = "guide"
    API_REFERENCE = "api-reference"
    ARCHITECTURE = "architecture"
    TUTORIAL = "tutorial"
    SPECIFICATION = "specification"
    REPORT = "report"
    TEMPLATE = "template"
    README = "readme"
    OTHER = "other"


@dataclass
class DocumentMetadata:
    """Document metadata"""
    doc_id: str
    path: str                           # Relative to project root
    title: str
    purpose: str                        # DocumentPurpose value
    status: str                         # DocumentStatus value
    created: str                        # ISO 8601 timestamp
    created_by: str                     # Agent/person name
    updated: str                        # ISO 8601 timestamp
    size: int                           # Bytes
    checksum: str                       # SHA-256 hex
    version: str                        # Project version
    tags: List[str]
    dependencies: List[str]             # Paths to related docs
    supersedes: Optional[str] = None    # Path to old version
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DocumentMetadata':
        """Create from dictionary"""
        return cls(**data)


# ============================================================================
# Document Registry
# ============================================================================

class DocumentRegistry:
    """
    Document metadata registry with security hardening

    Features:
    - Secure path validation
    - File size limits
    - Atomic file operations
    - Basic locking
    """

    def __init__(self, root_path: Path, registry_path: Optional[Path] = None):
        """
        Initialize document registry

        Args:
            root_path: Project root directory
            registry_path: Path to registry file (default: docs/DOCUMENT_REGISTRY.json)
        """
        self.root_path = root_path.resolve()

        if registry_path is None:
            registry_path = self.root_path / "docs" / "DOCUMENT_REGISTRY.json"

        self.registry_path = registry_path

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _load_registry(self) -> Dict[str, Dict[str, Any]]:
        """
        Load registry from file with locking (CRIT-05)

        Returns:
            Dictionary of doc_id -> metadata
        """
        if not self.registry_path.exists():
            return {}

        try:
            with open(self.registry_path, 'r', encoding='utf-8') as f:
                # Acquire shared lock for reading
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)

                try:
                    data = json.load(f)

                    # Validate JSON size (CRIT-04)
                    json_str = json.dumps(data)
                    if len(json_str) > SecurityConfig.MAX_METADATA_SIZE:
                        raise SecurityError(
                            f"Registry too large: {len(json_str)} bytes",
                            code="JSON-SIZE"
                        )

                    return data.get('documents', {})
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in registry: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
            return {}

    def _save_registry(self, documents: Dict[str, Dict[str, Any]]) -> None:
        """
        Save registry to file atomically with locking (CRIT-05)

        Args:
            documents: Dictionary of doc_id -> metadata
        """
        # Prepare data
        data = {
            'version': '1.0.0',
            'generated': datetime.now(timezone.utc).isoformat(),
            'total_documents': len(documents),
            'documents': documents
        }

        # Validate size before writing
        json_str = json.dumps(data, indent=2)
        if len(json_str) > SecurityConfig.MAX_METADATA_SIZE:
            raise SecurityError(
                f"Registry would exceed size limit: {len(json_str)} bytes",
                code="JSON-SIZE"
            )

        # Ensure directory exists
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write with locking
        try:
            with open(self.registry_path, 'w', encoding='utf-8') as f:
                # Acquire exclusive lock for writing
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)

                try:
                    f.write(json_str)
                    f.flush()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            self.logger.info(f"Registry saved: {len(documents)} documents")

        except Exception as e:
            self.logger.error(f"Failed to save registry: {e}")
            raise

    def add_document(
        self,
        file_path: Path,
        title: Optional[str] = None,
        purpose: str = "guide",
        created_by: str = "unknown",
        version: str = "unknown",
        tags: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        notes: str = ""
    ) -> DocumentMetadata:
        """
        Add document to registry

        Args:
            file_path: Path to document file
            title: Document title (default: infer from filename)
            purpose: Document purpose
            created_by: Creator name
            version: Project version
            tags: Document tags
            dependencies: Related document paths
            notes: Additional notes

        Returns:
            Created metadata

        Raises:
            SecurityError: If security validation fails
            FileNotFoundError: If file doesn't exist
        """
        # Security validation (CRIT-01, CRIT-02)
        validated_path = validate_path(file_path, self.root_path)

        # Check file size (CRIT-03)
        size = check_file_size(validated_path)

        # Calculate checksum
        checksum = calculate_checksum(validated_path)

        # Generate doc_id from path
        rel_path = str(validated_path.relative_to(self.root_path))
        doc_id = rel_path.replace('/', '-').replace('.', '-')

        # Infer title from filename if not provided
        if title is None:
            title = validated_path.stem.replace('_', ' ').replace('-', ' ').title()

        # Sanitize inputs
        title = sanitize_string(title, SecurityConfig.MAX_TITLE_LENGTH)
        notes = sanitize_string(notes, 1000)

        # Validate tags
        if tags is None:
            tags = []

        if len(tags) > SecurityConfig.MAX_TAGS:
            raise ValueError(f"Too many tags: {len(tags)} (max: {SecurityConfig.MAX_TAGS})")

        tags = [
            sanitize_string(tag, SecurityConfig.MAX_TAG_LENGTH)
            for tag in tags
        ]

        # Validate dependencies
        if dependencies is None:
            dependencies = []

        validated_deps = []
        for dep in dependencies:
            dep_path = self.root_path / dep
            validated_dep = validate_path(dep_path, self.root_path)
            validated_deps.append(str(validated_dep.relative_to(self.root_path)))

        # Create metadata
        now = datetime.now(timezone.utc).isoformat()

        metadata = DocumentMetadata(
            doc_id=doc_id,
            path=rel_path,
            title=title,
            purpose=purpose,
            status=DocumentStatus.CURRENT.value,
            created=now,
            created_by=created_by,
            updated=now,
            size=size,
            checksum=checksum,
            version=version,
            tags=tags,
            dependencies=validated_deps,
            notes=notes
        )

        # Load registry
        documents = self._load_registry()

        # Add/update document
        documents[doc_id] = metadata.to_dict()

        # Save registry
        self._save_registry(documents)

        self.logger.info(f"Document added: {doc_id} ({rel_path})")

        return metadata

    def get_document(self, doc_id: str) -> Optional[DocumentMetadata]:
        """
        Get document metadata by ID

        Args:
            doc_id: Document ID

        Returns:
            Metadata if found, None otherwise
        """
        documents = self._load_registry()

        if doc_id not in documents:
            return None

        return DocumentMetadata.from_dict(documents[doc_id])

    def list_documents(
        self,
        status: Optional[str] = None,
        purpose: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> List[DocumentMetadata]:
        """
        List documents with optional filtering

        Args:
            status: Filter by status
            purpose: Filter by purpose
            tags: Filter by tags (any match)

        Returns:
            List of matching documents
        """
        documents = self._load_registry()
        results = []

        for doc_data in documents.values():
            metadata = DocumentMetadata.from_dict(doc_data)

            # Apply filters
            if status and metadata.status != status:
                continue

            if purpose and metadata.purpose != purpose:
                continue

            if tags and not any(tag in metadata.tags for tag in tags):
                continue

            results.append(metadata)

        # Sort by path
        results.sort(key=lambda m: m.path)

        return results

    def update_status(self, doc_id: str, new_status: str) -> bool:
        """
        Update document status

        Args:
            doc_id: Document ID
            new_status: New status value

        Returns:
            True if updated, False if not found
        """
        documents = self._load_registry()

        if doc_id not in documents:
            return False

        documents[doc_id]['status'] = new_status
        documents[doc_id]['updated'] = datetime.now(timezone.utc).isoformat()

        self._save_registry(documents)

        self.logger.info(f"Document status updated: {doc_id} -> {new_status}")

        return True

    def remove_document(self, doc_id: str) -> bool:
        """
        Remove document from registry

        Args:
            doc_id: Document ID

        Returns:
            True if removed, False if not found
        """
        documents = self._load_registry()

        if doc_id not in documents:
            return False

        del documents[doc_id]

        self._save_registry(documents)

        self.logger.info(f"Document removed: {doc_id}")

        return True

    def validate_registry(self) -> Dict[str, List[str]]:
        """
        Validate registry integrity

        Returns:
            Dictionary with 'errors' and 'warnings' lists
        """
        documents = self._load_registry()
        errors = []
        warnings = []

        for doc_id, doc_data in documents.items():
            # Check if file exists
            file_path = self.root_path / doc_data['path']

            if not file_path.exists():
                errors.append(f"{doc_id}: File not found: {doc_data['path']}")
                continue

            # Check checksum
            try:
                current_checksum = calculate_checksum(file_path)
                if current_checksum != doc_data['checksum']:
                    warnings.append(f"{doc_id}: Checksum mismatch (file modified)")
            except Exception as e:
                errors.append(f"{doc_id}: Checksum calculation failed: {e}")

            # Check dependencies
            for dep in doc_data.get('dependencies', []):
                dep_path = self.root_path / dep
                if not dep_path.exists():
                    warnings.append(f"{doc_id}: Dependency not found: {dep}")

        return {
            'errors': errors,
            'warnings': warnings
        }


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Trinitas Document Registry - Secure documentation management'
    )

    parser.add_argument(
        '--root',
        type=Path,
        default=Path.cwd(),
        help='Project root directory (default: current directory)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Add command
    add_parser = subparsers.add_parser('add', help='Add document to registry')
    add_parser.add_argument('file', type=Path, help='Document file path')
    add_parser.add_argument('--title', help='Document title')
    add_parser.add_argument('--purpose', default='guide', help='Document purpose')
    add_parser.add_argument('--created-by', default='unknown', help='Creator name')
    add_parser.add_argument('--version', default='unknown', help='Project version')
    add_parser.add_argument('--tags', help='Comma-separated tags')
    add_parser.add_argument('--notes', default='', help='Additional notes')

    # List command
    list_parser = subparsers.add_parser('list', help='List documents')
    list_parser.add_argument('--status', help='Filter by status')
    list_parser.add_argument('--purpose', help='Filter by purpose')
    list_parser.add_argument('--tags', help='Filter by tags (comma-separated)')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate registry')

    # Update status command
    status_parser = subparsers.add_parser('update-status', help='Update document status')
    status_parser.add_argument('doc_id', help='Document ID')
    status_parser.add_argument('status', help='New status')

    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove document')
    remove_parser.add_argument('doc_id', help='Document ID')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize registry
    try:
        registry = DocumentRegistry(args.root)
    except Exception as e:
        print(f"Error: Failed to initialize registry: {e}", file=sys.stderr)
        return 1

    # Execute command
    try:
        if args.command == 'add':
            tags = args.tags.split(',') if args.tags else []

            metadata = registry.add_document(
                file_path=args.file,
                title=args.title,
                purpose=args.purpose,
                created_by=args.created_by,
                version=args.version,
                tags=tags,
                notes=args.notes
            )

            print(f"✅ Document added: {metadata.doc_id}")
            print(f"   Path: {metadata.path}")
            print(f"   Title: {metadata.title}")
            print(f"   Size: {metadata.size} bytes")

        elif args.command == 'list':
            tags = args.tags.split(',') if args.tags else None

            documents = registry.list_documents(
                status=args.status,
                purpose=args.purpose,
                tags=tags
            )

            print(f"\n📚 Found {len(documents)} documents:\n")

            for metadata in documents:
                print(f"  {metadata.doc_id}")
                print(f"    Path: {metadata.path}")
                print(f"    Title: {metadata.title}")
                print(f"    Status: {metadata.status}")
                print(f"    Created: {metadata.created}")
                print()

        elif args.command == 'validate':
            result = registry.validate_registry()

            if result['errors']:
                print(f"\n❌ {len(result['errors'])} errors found:\n")
                for error in result['errors']:
                    print(f"  - {error}")

            if result['warnings']:
                print(f"\n⚠️  {len(result['warnings'])} warnings:\n")
                for warning in result['warnings']:
                    print(f"  - {warning}")

            if not result['errors'] and not result['warnings']:
                print("\n✅ Registry is valid")

            return 1 if result['errors'] else 0

        elif args.command == 'update-status':
            success = registry.update_status(args.doc_id, args.status)

            if success:
                print(f"✅ Status updated: {args.doc_id} -> {args.status}")
            else:
                print(f"❌ Document not found: {args.doc_id}", file=sys.stderr)
                return 1

        elif args.command == 'remove':
            success = registry.remove_document(args.doc_id)

            if success:
                print(f"✅ Document removed: {args.doc_id}")
            else:
                print(f"❌ Document not found: {args.doc_id}", file=sys.stderr)
                return 1

    except SecurityError as e:
        print(f"🚨 Security error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
