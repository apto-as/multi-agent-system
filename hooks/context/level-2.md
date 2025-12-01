# Session Context

## Current Session Profile
- **Namespace**: ${TMWS_NAMESPACE}
- **Agent**: ${TMWS_AGENT_ID}
- **Mode**: Interactive

## Trinitas Protocol
When analyzing complex tasks, use phase-based execution:

1. **Strategic Planning** (Hera + Athena)
   - Architecture design and resource coordination
   - Both agents must agree before implementation

2. **Implementation** (Artemis)
   - Technical implementation following Clean Architecture
   - All tests must pass before verification

3. **Verification** (Hestia)
   - Security audit and final approval
   - Sign-off required for deployment

## Memory Integration
- Use `recall_memory` for relevant past context
- Apply learned patterns via `apply_pattern`
- Create memories with `create_memory`

## Active Context
This session inherits from previous conversations when available.
Use semantic search for relevant memories and patterns.
