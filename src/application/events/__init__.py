"""Event Dispatching Infrastructure

Responsible for dispatching domain events to registered handlers.
Events are dispatched AFTER transaction commit only.
"""
