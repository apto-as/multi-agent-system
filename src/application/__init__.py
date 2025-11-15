"""Application Service Layer

This layer orchestrates use cases, manages transactions, and dispatches domain events.

Responsibilities:
- Use case orchestration
- Transaction management (UnitOfWork)
- Domain event dispatching (after commit)
- DTO mapping (aggregate ↔ DTO)
- Authorization and validation
"""
