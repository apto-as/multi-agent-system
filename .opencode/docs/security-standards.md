# Security Standards and Audit Protocols

## Critical Security Rules
- **NEVER** commit API keys or tokens
- **NEVER** use eval() with user input
- **NEVER** construct SQL with concatenation
- **ALWAYS** validate user inputs
- **ALWAYS** use HTTPS in production

## Input Validation
```python
# Python example
from pydantic import BaseModel, validator

class UserInput(BaseModel):
    email: str
    age: int

    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email')
        return v
```

```javascript
// JavaScript example
function validateInput(input) {
  // Sanitize HTML
  const cleaned = DOMPurify.sanitize(input);

  // Validate length
  if (cleaned.length > 1000) {
    throw new Error('Input too long');
  }

  return cleaned;
}
```

## SQL Injection Prevention
```python
# Bad
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

## XSS Prevention
```javascript
// Bad
element.innerHTML = userInput;

// Good
element.textContent = userInput;

// When HTML is needed
element.innerHTML = DOMPurify.sanitize(userInput);
```

## Authentication & Authorization
- Use JWT or session tokens
- Implement rate limiting
- Add CSRF protection
- Enable 2FA for sensitive operations

## Security Audit Checklist
- [ ] Dependencies vulnerability scan
- [ ] Static code analysis
- [ ] Input validation implemented
- [ ] Authentication configured
- [ ] Authorization checks in place
- [ ] Sensitive data encrypted
- [ ] Audit logging enabled