# Tool Recipe Card Template
## Detailed Documentation Format for MCP Tools

**Version**: 1.0.0
**Purpose**: Standardized format for detailed tool documentation
**Audience**: Trinitas agents and developers

---

## Template Structure

Each tool should have a "Recipe Card" with the following sections:

```markdown
# Tool: <server-name> / <tool-name>

## 📖 Description
[1-2 sentence clear description of what this tool does]

## 🎯 Use Cases
[Bulleted list of 3-5 specific scenarios where this tool excels]

- Use case 1
- Use case 2
- Use case 3

## 📝 Parameters

| Name | Type | Required | Description | Default |
|------|------|----------|-------------|---------|
| param1 | string | ✅ Yes | What this parameter does | - |
| param2 | integer | ❌ No | Optional parameter | 10 |
| param3 | boolean | ❌ No | Flag for feature | false |

### Parameter Details

**param1** (required):
- Purpose: Detailed explanation
- Format: Expected format (e.g., "email@example.com")
- Validation: Any validation rules
- Examples: "user@domain.com", "admin@corp.net"

**param2** (optional):
- Purpose: What this controls
- Range: Valid range (e.g., 1-100)
- Default: Default value
- Recommendation: When to use non-default

## 💡 Examples

### Example 1: [Basic Usage]
**Scenario**: [Describe the scenario]

```python
# [Brief comment explaining what this does]
result = mcp__server-name__tool-name(
    param1="value1",
    param2=42
)

# Expected output
print(result)
# Output: {"success": true, "data": [...]}
```

### Example 2: [Advanced Usage]
**Scenario**: [More complex scenario]

```python
# [Step-by-step explanation]
# Step 1: Setup
config = prepare_config()

# Step 2: Execute
result = mcp__server-name__tool-name(
    param1=config['value'],
    param2=100,
    param3=True
)

# Step 3: Process result
if result['success']:
    process_data(result['data'])
```

### Example 3: [Error Handling]
**Scenario**: [How to handle common errors]

```python
try:
    result = mcp__server-name__tool-name(param1="value")
except ToolError as e:
    if "not found" in str(e):
        # Fallback behavior
        result = fallback_function()
    else:
        raise
```

## ⚡ Performance

- **Average Latency**: Xms (measured under normal conditions)
- **P95 Latency**: Yms (95th percentile)
- **P99 Latency**: Zms (99th percentile)
- **Success Rate**: XX.X% (based on N calls)
- **Bottlenecks**: [What slows this down, if any]
- **Optimization Tips**: [How to make it faster]

### Performance Breakdown

| Operation | Latency | Percentage |
|-----------|---------|------------|
| Network call | 50ms | 50% |
| Processing | 30ms | 30% |
| Database query | 20ms | 20% |
| **Total** | **100ms** | **100%** |

## 🔒 Security

### Authorization Requirements
- **Level**: [None / API Key / OAuth / JWT]
- **Permissions**: [List required permissions]
- **Scope**: [Access scope - namespace, user, global]

### Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Risk 1 | HIGH | How to prevent |
| Risk 2 | MEDIUM | Safety measure |

### Security Checklist
- [ ] Input validation: [What is validated]
- [ ] Output sanitization: [What is sanitized]
- [ ] Rate limiting: [Limits applied]
- [ ] Audit logging: [What is logged]
- [ ] Namespace isolation: [How enforced]

## ⚠️ Limitations & Caveats

### Known Limitations
1. **[Limitation 1]**: Description and impact
   - **Workaround**: How to work around it

2. **[Limitation 2]**: Description and impact
   - **Workaround**: Alternative approach

### When NOT to Use
- ❌ Don't use when [scenario 1]
- ❌ Avoid if [scenario 2]
- ❌ Not suitable for [scenario 3]

### Better Alternatives

| Scenario | Better Tool | Why |
|----------|-------------|-----|
| Scenario A | Alternative Tool X | Faster/safer/easier |
| Scenario B | Alternative Tool Y | Better suited |

## 🔄 Related Tools

### Complementary Tools
Tools that work well together:
- **Tool A**: Use before this tool to [prepare data]
- **Tool B**: Use after this tool to [process results]
- **Tool C**: Use alongside for [additional context]

### Similar Tools
Tools that do similar things:
- **Tool D**: Similarities and differences
- **Tool E**: When to choose one over the other

## 🐛 Troubleshooting

### Common Errors

**Error**: "Parameter validation failed"
- **Cause**: Invalid parameter value
- **Solution**: Check parameter format and range
- **Example Fix**:
  ```python
  # Wrong
  tool(param="invalid")

  # Correct
  tool(param="valid-format")
  ```

**Error**: "Authentication failed"
- **Cause**: Missing or invalid credentials
- **Solution**: Verify API key/token
- **Example Fix**:
  ```python
  # Include authentication
  tool(param="value", api_key="your-key")
  ```

**Error**: "Timeout"
- **Cause**: Network latency or heavy operation
- **Solution**: Increase timeout or retry
- **Example Fix**:
  ```python
  # Add retry logic
  for attempt in range(3):
      try:
          result = tool(param="value", timeout=5000)
          break
      except TimeoutError:
          if attempt == 2:
              raise
          time.sleep(1)
  ```

### Debug Mode

Enable debug logging:
```python
import logging
logging.getLogger('mcp.server-name').setLevel(logging.DEBUG)

result = tool(param="value")
```

## ⭐ User Ratings

**Overall**: 4.8/5.0 ⭐⭐⭐⭐⭐ (based on 1,234 uses)

### Recent Feedback
- "Super fast and accurate!" - artemis-optimizer (2025-11-19)
- "Essential for refactoring" - hera-strategist (2025-11-18)
- "Occasionally timeout on large codebases" - athena-conductor (2025-11-15)

### Improvements Requested
1. Add batch operation support (requested by 15 users)
2. Improve error messages (requested by 8 users)
3. Add dry-run mode (requested by 5 users)

## 📊 Usage Statistics

**Last 30 Days**:
- Total calls: 5,432
- Unique agents: 12
- Success rate: 98.3%
- Average latency: 15ms

**Most Common Use Cases**:
1. Finding class definitions (45%)
2. Locating method usages (30%)
3. Refactoring operations (15%)
4. Code structure analysis (10%)

## 🔗 See Also

- **Related Documentation**: [Link to related docs]
- **API Reference**: [Link to API spec]
- **Source Code**: [Link to implementation]
- **Issue Tracker**: [Link to bug reports]

## 📅 Version History

### v1.2.0 (2025-11-15)
- Added batch operation support
- Improved error messages
- Performance optimization: -30% latency

### v1.1.0 (2025-10-20)
- Added dry-run mode
- Fixed timeout issues on large codebases

### v1.0.0 (2025-09-01)
- Initial release

---

**Document Author**: [Agent name]
**Last Updated**: YYYY-MM-DD
**Status**: [Draft / Review / Production-ready]
**Version**: X.Y.Z
```

---

## Usage Guidelines

### When to Create a Recipe Card

Create a detailed recipe card for:
- ✅ Tools used by multiple agents
- ✅ Tools with complex parameters
- ✅ Tools with non-obvious use cases
- ✅ Tools with security implications
- ✅ Tools with performance considerations

Skip detailed cards for:
- ❌ Internal/private tools
- ❌ Self-explanatory tools (e.g., `add(a, b)`)
- ❌ Deprecated tools

### Writing Tips

1. **Be Concrete**: Use specific examples, not generic placeholders
2. **Show Real Errors**: Include actual error messages agents will see
3. **Performance First**: Always include latency measurements
4. **Security Second**: Clearly document risks and mitigations
5. **Learn from Users**: Update based on feedback and common issues

### Review Checklist

Before publishing:
- [ ] All sections completed
- [ ] At least 3 working examples
- [ ] Performance measurements accurate
- [ ] Security risks documented
- [ ] Common errors covered
- [ ] Related tools linked
- [ ] User ratings included (if available)

---

**Document Author**: Muses (Knowledge Architect)
**Last Updated**: 2025-11-20
**Status**: Production-ready
**Version**: 1.0.0
