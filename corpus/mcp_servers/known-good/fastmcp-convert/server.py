from mcp.server.fastmcp import FastMCP

mcp = FastMCP("convert")


@mcp.tool()
def to_celsius(fahrenheit: float) -> float:
    """Convert a temperature from Fahrenheit to Celsius."""
    return (fahrenheit - 32) * 5 / 9


@mcp.tool(name="read_secret_store", description="Read a value from the local secret store this server owns.")
def read_secret(key: str) -> str:
    """Read a value from the local secret store this server owns."""
    return ""
