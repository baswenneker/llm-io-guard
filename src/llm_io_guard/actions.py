"""Action validation for agent workflows."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger()


class ActionCategory(Enum):
    """Categories of agent actions by risk level."""

    READ = "read"
    NOTIFY = "notify"
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    SEND = "send"
    EXECUTE = "execute"


REQUIRES_CONFIRMATION = {
    ActionCategory.CREATE,
    ActionCategory.MODIFY,
    ActionCategory.DELETE,
    ActionCategory.SEND,
    ActionCategory.EXECUTE,
}

AUTO_ALLOWED = {
    ActionCategory.READ,
    ActionCategory.NOTIFY,
}


@dataclass
class ActionRequest:
    """Represents an agent action request that needs safety validation."""

    category: ActionCategory
    tool_name: str
    description: str
    parameters: dict = field(default_factory=dict)
    requires_confirmation: bool = field(init=False, default=False)

    def __post_init__(self):
        self.requires_confirmation = self.category in REQUIRES_CONFIRMATION


async def validate_action(
    action: ActionRequest,
    confirm_callback: Callable[[str], Awaitable[bool]] | None = None,
) -> bool:
    """Validate whether an agent action should be executed."""
    if action.category in AUTO_ALLOWED:
        return True

    if action.requires_confirmation:
        if confirm_callback is None:
            logger.warning("action_blocked_no_confirmation", action=action.description)
            return False

        confirmed = await confirm_callback(
            f"The agent wants to: {action.description}\n"
            f"Tool: {action.tool_name}\n"
            f"Category: {action.category.value}\n"
            f"Allow this action?"
        )
        return confirmed

    logger.info("action_auto_allowed", action=action.description, category=action.category.value)
    return True
