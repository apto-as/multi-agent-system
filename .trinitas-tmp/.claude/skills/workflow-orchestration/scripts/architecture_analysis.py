"""
Architecture Analysis Skill - Athena

Analyzes codebase architecture, identifies patterns, evaluates design quality,
and provides architectural recommendations.

Author: Artemis (Technical Perfectionist)
Version: 1.0.0
Date: 2025-11-07
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Security-related error (CWE-22, CWE-61)."""
    pass


def validate_path_security(
    path: Path,
    allowed_roots: Optional[List[Path]] = None,
    require_within_cwd: bool = True
) -> Path:
    """
    Validate path is safe (CWE-22, CWE-61 prevention).

    Args:
        path: Path to validate
        allowed_roots: List of allowed root directories. If None and require_within_cwd=True,
                      uses current working directory. If None and require_within_cwd=False,
                      skips path traversal check.
        require_within_cwd: If True and allowed_roots is None, restricts to current working directory.

    Returns:
        Path: Resolved safe path

    Raises:
        SecurityError: If path is a symlink or outside allowed roots

    Security Checks:
        - CWE-61: Symlink access prevention
        - CWE-22: Path traversal prevention (when allowed_roots is specified)

    Example:
        >>> safe_path = validate_path_security(Path("./my_project"))
    """
    # Check for symlink (CWE-61)
    if path.is_symlink():
        logger.error(f"Security: Symlink access denied (CWE-61): {path}")
        raise SecurityError(f"Symlink access denied (CWE-61): {path}")

    # Resolve the path (without strict=True to allow path traversal detection)
    try:
        resolved = path.resolve()
    except RuntimeError as e:
        logger.error(f"Security: Path resolution failed: {path} - {e}")
        raise SecurityError(f"Invalid path: {path}")

    # If allowed_roots is None and require_within_cwd, use current directory
    if allowed_roots is None:
        if require_within_cwd:
            allowed_roots = [Path.cwd()]
        else:
            # No path traversal check - only symlink check was performed
            logger.debug(f"Security: Path validated (symlink check only): {resolved}")
            return resolved

    # Check path is within allowed roots (CWE-22)
    is_within_allowed = False
    for root in allowed_roots:
        try:
            resolved_root = root.resolve()
            resolved.relative_to(resolved_root)
            is_within_allowed = True
            break
        except ValueError:
            continue

    if not is_within_allowed:
        logger.error(
            f"Security: Path traversal attempt (CWE-22): {path} "
            f"(resolved: {resolved}, allowed roots: {[str(r) for r in allowed_roots]})"
        )
        raise SecurityError(
            f"Path traversal attempt (CWE-22): {path} is outside allowed directories"
        )

    logger.debug(f"Security: Path validated successfully: {resolved}")
    return resolved


async def analyze_architecture(
    monitor: Any,
    project_path: str,
    include_dependencies: bool = True,
    depth: int = 3
) -> Dict[str, Any]:
    """
    Analyze project architecture and design patterns.

    Args:
        monitor: Execution monitor for logging and progress tracking
        project_path: Path to the project directory
        include_dependencies: Whether to analyze dependencies
        depth: Maximum directory depth to analyze

    Returns:
        dict: Architecture analysis result with metrics and recommendations

    Example:
        result = await analyze_architecture(monitor, "./my_project")
        print(result["metrics"]["total_modules"])
    """
    logger.info(f"Starting architecture analysis: {project_path}")

    try:
        # Security: Validate path before processing (CWE-22, CWE-61)
        project_input = Path(project_path)

        # Validate the path is safe
        # SECURITY: Always enforce path traversal check (CWE-22)
        # Symlink attacks (CWE-61) are also prevented
        try:
            project = validate_path_security(project_input, require_within_cwd=True)
        except SecurityError as e:
            logger.error(f"Security validation failed: {e}")
            return {
                "status": "error",
                "error": f"Security validation failed: {e}",
                "data": None
            }

        if not project.exists():
            return {
                "status": "error",
                "error": f"Project path not found: {project_path}",
                "data": None
            }

        if not project.is_dir():
            return {
                "status": "error",
                "error": f"Path is not a directory: {project_path}",
                "data": None
            }

        # Phase 1: Discover modules and components
        logger.info("Phase 1: Discovering modules...")
        modules = await _discover_modules(project, depth)

        # Phase 2: Analyze dependencies
        dependencies = {}
        if include_dependencies:
            logger.info("Phase 2: Analyzing dependencies...")
            dependencies = await _analyze_dependencies(project, modules)

        # Phase 3: Identify patterns
        logger.info("Phase 3: Identifying architectural patterns...")
        patterns = await _identify_patterns(modules, dependencies)

        # Phase 4: Calculate metrics
        logger.info("Phase 4: Calculating metrics...")
        metrics = await _calculate_metrics(modules, dependencies)

        # Phase 5: Generate recommendations
        logger.info("Phase 5: Generating recommendations...")
        recommendations = await _generate_recommendations(
            modules, dependencies, patterns, metrics
        )

        result = {
            "status": "success",
            "data": {
                "project_path": str(project),
                "modules": modules,
                "dependencies": dependencies,
                "patterns": patterns,
                "recommendations": recommendations
            },
            "metrics": metrics,
            "summary": {
                "total_modules": len(modules),
                "total_dependencies": len(dependencies),
                "identified_patterns": len(patterns),
                "architecture_score": metrics.get("architecture_score", 0.0)
            }
        }

        logger.info(
            f"Architecture analysis completed: "
            f"{len(modules)} modules, "
            f"score: {metrics.get('architecture_score', 0.0):.2f}"
        )

        return result

    except Exception as e:
        logger.error(f"Architecture analysis failed: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "data": None
        }


async def _discover_modules(project: Path, max_depth: int) -> List[Dict[str, Any]]:
    """Discover all modules in the project."""
    modules = []

    def _scan_directory(path: Path, current_depth: int = 0):
        if current_depth > max_depth:
            return

        try:
            # Use os.scandir() for better control over symlink handling
            with os.scandir(path) as entries:
                for entry in entries:
                    # Security: Skip hidden files (CWE-61)
                    if entry.name.startswith("."):
                        continue

                    # Security: Skip symlinks WITHOUT following them (CWE-61)
                    # Use entry.is_symlink() which doesn't follow symlinks
                    if entry.is_symlink():
                        logger.warning(f"Skipping symlink (CWE-61): {entry.path}")
                        continue

                    # Now we can safely check if it's a directory
                    # Use entry.is_dir(follow_symlinks=False) to be extra safe
                    if entry.is_dir(follow_symlinks=False):
                        item_path = Path(entry.path)
                        # Check for __init__.py to identify Python packages
                        init_file = item_path / "__init__.py"
                        # Verify __init__.py is not a symlink before considering it
                        if init_file.exists() and not init_file.is_symlink():
                            modules.append({
                                "name": entry.name,
                                "path": str(item_path.relative_to(project)),
                                "type": "package",
                                "depth": current_depth
                            })
                        _scan_directory(item_path, current_depth + 1)
                    elif entry.is_file(follow_symlinks=False):
                        # Check file extension
                        if entry.name.endswith((".py", ".js", ".ts")):
                            item_path = Path(entry.path)
                            suffix = item_path.suffix
                            modules.append({
                                "name": item_path.stem,
                                "path": str(item_path.relative_to(project)),
                                "type": "module",
                                "language": suffix[1:],
                                "depth": current_depth
                            })
        except PermissionError as e:
            logger.warning(f"Permission denied while scanning {path}: {e}")
        except Exception as e:
            logger.error(f"Error scanning directory {path}: {e}")

    # Simulate async I/O with await
    await asyncio.sleep(0.01)
    _scan_directory(project)

    return modules


async def _analyze_dependencies(
    project: Path,
    modules: List[Dict[str, Any]]
) -> Dict[str, List[str]]:
    """Analyze dependencies between modules."""
    dependencies = {}

    # Simulate dependency analysis
    await asyncio.sleep(0.02)

    # Example: detect circular dependencies, coupling metrics
    for module in modules:
        module_name = module["name"]
        dependencies[module_name] = []

        # Simple heuristic: modules in same directory have dependencies
        module_dir = Path(module["path"]).parent
        for other in modules:
            if other["name"] == module_name:
                continue
            other_dir = Path(other["path"]).parent
            if module_dir == other_dir and other["type"] == "module":
                dependencies[module_name].append(other["name"])

    return dependencies


async def _identify_patterns(
    modules: List[Dict[str, Any]],
    dependencies: Dict[str, List[str]]
) -> List[Dict[str, Any]]:
    """Identify architectural patterns (MVC, layered, microservices, etc.)."""
    patterns = []

    await asyncio.sleep(0.01)

    # Detect layered architecture
    layers = {"controller", "service", "repository", "model", "view"}
    detected_layers = set()

    for module in modules:
        for layer in layers:
            if layer in module["name"].lower():
                detected_layers.add(layer)

    if len(detected_layers) >= 3:
        patterns.append({
            "name": "Layered Architecture",
            "confidence": 0.85,
            "layers": list(detected_layers)
        })

    # Detect microservices pattern
    service_count = sum(1 for m in modules if "service" in m["name"].lower())
    if service_count >= 3:
        patterns.append({
            "name": "Microservices",
            "confidence": 0.70,
            "service_count": service_count
        })

    return patterns


async def _calculate_metrics(
    modules: List[Dict[str, Any]],
    dependencies: Dict[str, List[str]]
) -> Dict[str, Any]:
    """Calculate architecture quality metrics."""
    await asyncio.sleep(0.01)

    # Cohesion metric (modules per package)
    packages = [m for m in modules if m["type"] == "package"]
    all_modules = [m for m in modules if m["type"] == "module"]

    cohesion = len(all_modules) / max(len(packages), 1)

    # Coupling metric (average dependencies per module)
    total_deps = sum(len(deps) for deps in dependencies.values())
    coupling = total_deps / max(len(dependencies), 1)

    # Depth metric
    avg_depth = sum(m["depth"] for m in modules) / max(len(modules), 1)

    # Architecture score (0-100)
    # Lower coupling is better, moderate cohesion is good, shallow depth is better
    architecture_score = max(0, min(100, (
        (10 - min(coupling, 10)) * 5 +  # Coupling (0-50)
        min(cohesion, 10) * 3 +          # Cohesion (0-30)
        (5 - min(avg_depth, 5)) * 4      # Depth (0-20)
    )))

    return {
        "total_modules": len(modules),
        "total_packages": len(packages),
        "cohesion": round(cohesion, 2),
        "coupling": round(coupling, 2),
        "average_depth": round(avg_depth, 2),
        "architecture_score": round(architecture_score, 2)
    }


async def _generate_recommendations(
    modules: List[Dict[str, Any]],
    dependencies: Dict[str, List[str]],
    patterns: List[Dict[str, Any]],
    metrics: Dict[str, Any]
) -> List[Dict[str, str]]:
    """Generate architectural improvement recommendations."""
    recommendations = []

    await asyncio.sleep(0.01)

    # High coupling warning
    if metrics["coupling"] > 5:
        recommendations.append({
            "priority": "high",
            "category": "coupling",
            "message": f"High coupling detected (avg: {metrics['coupling']}). "
                      "Consider dependency injection and interface segregation."
        })

    # Low cohesion warning
    if metrics["cohesion"] < 2:
        recommendations.append({
            "priority": "medium",
            "category": "cohesion",
            "message": f"Low cohesion detected ({metrics['cohesion']}). "
                      "Consider grouping related modules into packages."
        })

    # Deep nesting warning
    if metrics["average_depth"] > 4:
        recommendations.append({
            "priority": "medium",
            "category": "structure",
            "message": f"Deep directory nesting (avg: {metrics['average_depth']}). "
                      "Consider flattening the structure for better maintainability."
        })

    # Pattern-based recommendations
    if not patterns:
        recommendations.append({
            "priority": "low",
            "category": "patterns",
            "message": "No clear architectural pattern detected. "
                      "Consider adopting a recognized pattern (MVC, layered, etc.)."
        })

    # Positive feedback
    if metrics["architecture_score"] >= 80:
        recommendations.append({
            "priority": "info",
            "category": "quality",
            "message": f"Excellent architecture score: {metrics['architecture_score']}/100. "
                      "Keep maintaining these standards!"
        })

    return recommendations
