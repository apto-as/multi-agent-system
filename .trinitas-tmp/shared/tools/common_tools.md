# Trinitas Agent Common Tools Configuration

## Standard Tool Set

All Trinitas agents have access to the following standardized tool set:

### Core File Operations
- **Read**: File content reading and analysis
- **Write**: File creation and complete content replacement
- **Edit**: Precise text modifications and replacements
- **MultiEdit**: Batch editing operations for efficiency

### System Operations
- **Bash**: Command execution and system interaction
- **Grep**: Advanced pattern searching across codebases
- **Glob**: File pattern matching and discovery

### Task Management
- **TodoWrite**: Progress tracking and task organization

## Tool Usage Guidelines

### Performance Optimization
- Use **MultiEdit** for batch operations instead of multiple **Edit** calls
- Prefer **Grep** over **Bash** grep commands for better performance
- Use **Glob** for file discovery before **Grep** operations

### Quality Standards
- Always validate file paths before operations
- Use atomic operations where possible
- Implement proper error handling and rollback strategies

---
*This configuration is shared across all Trinitas agents for consistency and optimal performance.*