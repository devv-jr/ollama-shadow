import json
from pathlib import Path


def get_tool_definitions() -> list[dict]:
    schema_path = Path(__file__).parent.parent / "data" / "tools.json"
    with open(schema_path, "r") as f:
        return json.load(f)
