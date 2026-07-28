"""First-party billing helpers."""

RATE = 0.19


def gross(net: float) -> float:
    return round(net * (1 + RATE), 2)
