#!/usr/bin/env python3
"""
Minimal Protocol Injector for Trinitas-Core
Only handles SessionStart and PreCompact protocol injection
All other functionality has been moved to trinitas-mcp
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

class ProtocolInjector:
    """Minimal protocol injector for TRINITAS-CORE-PROTOCOL.md"""
    
    def __init__(self):
        """Initialize with protocol file path from env or defaults"""
        # Load .env file if it exists
        env_path = Path(__file__).parent.parent / '.env'
        if env_path.exists():
            self._load_env(env_path)
        
        # Get protocol file path
        self.protocol_file = os.getenv(
            'PROTOCOL_FILE',
            os.path.expanduser('~/.claude/TRINITAS-CORE-PROTOCOL.md')
        )
        
        # Check if injection is enabled
        self.enabled = os.getenv('PROTOCOL_INJECTION_ENABLED', 'true').lower() == 'true'
    
    def _load_env(self, env_path: Path):
        """Load .env file without using dotenv library"""
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
        except Exception as e:
            print(f"Warning: Could not load .env: {e}", file=sys.stderr)
    
    def load_protocol(self) -> Optional[str]:
        """Load protocol content from file"""
        if not self.enabled:
            return None
        
        try:
            with open(self.protocol_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Extract key sections for injection
            sections = []
            
            # Add header
            sections.append("# 🌟 Trinitas-Core Protocol Active")
            sections.append(f"[Loaded from: {self.protocol_file}]")
            sections.append("")
            
            # Extract MCP Tools section if it exists
            if "## 🎯 実際のMCPツール実行方法" in content:
                start = content.find("## 🎯 実際のMCPツール実行方法")
                end = content.find("\n## ", start + 1)
                if end == -1:
                    mcp_section = content[start:]
                else:
                    mcp_section = content[start:end]
                sections.append(mcp_section)
            
            # Add reminder about available personas
            sections.append("\n## 📌 Available Personas")
            sections.append("- **Athena**: Harmonious Conductor - orchestration, workflow")
            sections.append("- **Artemis**: Technical Perfectionist - optimization, performance")
            sections.append("- **Hestia**: Security Guardian - security, audit, risk")
            sections.append("- **Eris**: Tactical Coordinator - coordination, team")
            sections.append("- **Hera**: Strategic Commander - strategy, planning")
            sections.append("- **Muses**: Knowledge Architect - documentation, knowledge")
            sections.append("\nUse TMWS MCP tools for persona execution and collaboration.")
            
            return "\n".join(sections)
            
        except FileNotFoundError:
            return "# Trinitas-Core Protocol\n[Protocol file not found, using default configuration]"
        except Exception as e:
            return f"# Trinitas-Core Protocol\n[Error loading protocol: {e}]"
    
    def inject_session_start(self):
        """Inject protocol at session start"""
        protocol_content = self.load_protocol()
        if protocol_content:
            # Output JSON for SessionStart hook
            output = {
                "systemMessage": protocol_content
            }
            print(json.dumps(output, ensure_ascii=False))
        else:
            print(json.dumps({"systemMessage": "Trinitas-Core Ready"}))
    
    def inject_pre_compact(self):
        """Inject protocol reminder before context compression"""
        if not self.enabled:
            return
        
        # Output reminder for PreCompact
        reminder = """
---
# Trinitas-Core Context Preservation

When creating the compact summary, preserve:
1. **Persona Usage**: Which personas were involved and their contributions
2. **MCP Tool Calls**: Important mcp__trinitas-mcp__ commands used
3. **Decision Rationale**: Why specific approaches were chosen
4. **Technical Details**: Critical implementation specifics
5. **Security Concerns**: Any risks or vulnerabilities identified

Remember to maintain the five-persona perspective in the summary.
---
        """
        print(reminder)
        
        # Also output brief protocol path
        print(f"\n[Trinitas Protocol Active - Source: {self.protocol_file}]")
    
    def test(self):
        """Test protocol injection functionality"""
        print("Testing Trinitas Protocol Injector...")
        print(f"Protocol file: {self.protocol_file}")
        print(f"Injection enabled: {self.enabled}")
        print(f"File exists: {Path(self.protocol_file).exists()}")
        
        if self.enabled and Path(self.protocol_file).exists():
            content = self.load_protocol()
            if content:
                print(f"Protocol loaded successfully ({len(content)} chars)")
                print("\nFirst 500 chars:")
                print(content[:500])
            else:
                print("Failed to load protocol content")
        else:
            print("Protocol injection disabled or file not found")
        
        return 0

def main():
    """Main entry point"""
    injector = ProtocolInjector()
    
    # Get hook type from argument or environment
    if len(sys.argv) > 1:
        hook_type = sys.argv[1]
    else:
        hook_event = os.getenv('CLAUDE_HOOK_EVENT', '')
        if hook_event == 'SessionStart':
            hook_type = 'session_start'
        elif hook_event == 'PreCompact':
            hook_type = 'pre_compact'
        else:
            hook_type = 'test'
    
    # Execute based on hook type
    if hook_type == 'session_start':
        injector.inject_session_start()
    elif hook_type == 'pre_compact':
        injector.inject_pre_compact()
    elif hook_type == 'test':
        sys.exit(injector.test())
    else:
        print(f"Unknown hook type: {hook_type}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()