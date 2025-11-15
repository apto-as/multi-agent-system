"""Event Dispatcher Interface

Abstract interface for event dispatching.
"""

from abc import ABC, abstractmethod
from typing import Callable, List

from src.domain.events import DomainEvent


class EventDispatcher(ABC):
    """Abstract event dispatcher interface"""

    @abstractmethod
    def register(self, event_type: type[DomainEvent], handler: Callable):
        """Register event handler for specific event type"""
        pass

    @abstractmethod
    async def dispatch_all(self, events: List[DomainEvent]):
        """Dispatch all events to registered handlers"""
        pass
