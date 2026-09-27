def defang_ioc(value: str, ioc_type: str) -> str:
    """Make an IOC safe to share — prevents accidental resolution."""
    if ioc_type == "ip":
        parts = value.rsplit(".", 1)
        return "[.]".join(parts) if len(parts) == 2 else value
    if ioc_type == "domain":
        return value.replace(".", "[.]")
    if ioc_type == "url":
        return (
            value.replace("http://", "hxxp://")
                 .replace("https://", "hxxps://")
                 .replace(".", "[.]", 2)
        )
    return value
