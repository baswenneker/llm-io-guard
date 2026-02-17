# ruff: noqa: N999
"""ReAct Agent implementation using LangGraph.

This module provides a ReAct (Reasoning + Acting) agent that uses
LangGraph's StateGraph with TypedDict state, ToolNode for tool execution,
and the prebuilt tools_condition for routing decisions.

Example:
    >>> from llm_io_guard.agents import create_react_agent
    >>> agent = create_react_agent()
    >>> result = agent.invoke(
    ...     {"messages": [("user", "What's the weather in Paris?")]},
    ...     config={"configurable": {"thread_id": "1"}}
    ... )
"""

from typing import Annotated, Sequence

from langchain_core.messages import BaseMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from typing_extensions import TypedDict

from utils import get_logger

logger = get_logger(__name__)


class AgentState(TypedDict):
    """State for the ReAct agent.

    Attributes:
        messages: The conversation history with automatic message aggregation.
    """

    messages: Annotated[Sequence[BaseMessage], add_messages]


@tool
def get_weather(location: str) -> str:
    """Get the current weather for a location.

    Args:
        location: The city or location to get weather for.

    Returns:
        A string describing the current weather conditions.
    """
    logger.info("get_weather_called", location=location)
    # Simulated weather data
    weather_data = {
        "paris": "Sunny, 22°C with light clouds",
        "london": "Overcast, 15°C with chance of rain",
        "new york": "Clear, 28°C and humid",
        "tokyo": "Partly cloudy, 25°C",
    }
    location_lower = location.lower()
    for city, weather in weather_data.items():
        if city in location_lower:
            return f"Weather in {location}: {weather}"
    return f"Weather in {location}: Mild, 20°C with variable conditions"


@tool
def search(query: str) -> str:
    """Search for information on a given topic.

    Args:
        query: The search query string.

    Returns:
        Search results as a string.
    """
    logger.info("search_called", query=query)
    # Simulated search results
    return f"Search results for '{query}': Found relevant information about {query}. This is a simulated search result."


@tool
def calculate(expression: str) -> str:
    """Evaluate a mathematical expression.

    Args:
        expression: A mathematical expression to evaluate (e.g., '2 + 2', '10 * 5').

    Returns:
        The result of the calculation as a string.
    """
    logger.info("calculate_called", expression=expression)
    try:
        # Using eval with restricted builtins for safety
        allowed_names = {"__builtins__": {}}
        result = eval(expression, allowed_names, {})  # noqa: S307
        return f"Result: {expression} = {result}"
    except Exception as e:
        return f"Error calculating '{expression}': {e!s}"


# Default tools for the ReAct agent
DEFAULT_TOOLS = [get_weather, search, calculate]


def create_react_agent(
    model: str = "gpt-4o-mini",
    temperature: float = 0.0,
    tools: list | None = None,
    checkpointer: MemorySaver | None = None,
) -> CompiledStateGraph:
    """Create a ReAct agent using LangGraph.

    This function builds a StateGraph-based ReAct agent that:
    - Uses TypedDict for state management
    - Employs ToolNode for tool execution with error handling
    - Uses the prebuilt tools_condition for routing decisions
    - Supports conversation persistence via checkpointer

    Args:
        model: The OpenAI model to use. Defaults to "gpt-4o-mini".
        temperature: The temperature for LLM responses. Defaults to 0.0.
        tools: List of tools for the agent. Defaults to [get_weather, search, calculate].
        checkpointer: Memory saver for conversation persistence. Defaults to a new MemorySaver.

    Returns:
        A compiled StateGraph that can be invoked with messages.

    Example:
        >>> agent = create_react_agent()
        >>> result = agent.invoke(
        ...     {"messages": [("user", "Calculate 15 * 7")]},
        ...     config={"configurable": {"thread_id": "session1"}}
        ... )
        >>> print(result["messages"][-1].content)
    """
    logger.info("create_react_agent_called", model=model, temperature=temperature)

    if tools is None:
        tools = DEFAULT_TOOLS

    if checkpointer is None:
        checkpointer = MemorySaver()

    # Create LLM with tools bound
    llm = ChatOpenAI(model=model, temperature=temperature)
    llm_with_tools = llm.bind_tools(tools)

    # Create the tool node with error handling
    tool_node = ToolNode(tools, handle_tool_errors=True)

    def agent_node(state: AgentState) -> dict:
        """Process the current state and generate a response."""
        logger.debug("agent_node_called", message_count=len(state["messages"]))
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response]}

    # Build the graph
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)

    # Add edges
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")

    # Compile with checkpointer for memory persistence
    compiled_graph = graph.compile(checkpointer=checkpointer)

    logger.info("react_agent_created", tool_count=len(tools))
    return compiled_graph
