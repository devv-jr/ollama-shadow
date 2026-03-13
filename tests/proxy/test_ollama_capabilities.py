from airecon.proxy.ollama import (
    _detect_model_capabilities,
    _detect_model_capabilities_from_show,
)


def test_detects_reasoning_models_from_ollama_families() -> None:
    thinking, native_tools = _detect_model_capabilities("qwen3:32b")
    assert thinking is True
    assert native_tools is True


def test_detects_registry_prefixed_models() -> None:
    thinking, native_tools = _detect_model_capabilities("ollama.com/library/deepseek-r1:8b")
    assert thinking is True
    assert native_tools is False


def test_does_not_assume_native_tools_from_generic_version_pattern() -> None:
    thinking, native_tools = _detect_model_capabilities("gemini-2.5:latest")
    assert thinking is False
    assert native_tools is False


def test_detects_native_tools_for_known_tool_calling_families() -> None:
    thinking, native_tools = _detect_model_capabilities("firefunction:v2")
    assert thinking is False
    assert native_tools is True


def test_prefers_show_metadata_for_thinking_and_tools() -> None:
    show_data = {
        "capabilities": ["tools"],
        "template": "System prompt with <thinking> blocks",
    }
    thinking, native_tools = _detect_model_capabilities_from_show("custom:latest", show_data)
    assert thinking is True
    assert native_tools is True


def test_tools_without_thinking_are_not_enabled_for_airecon() -> None:
    show_data = {
        "capabilities": ["tools"],
        "template": "No reasoning tags",
        "modelfile": "FROM x",
    }
    thinking, native_tools = _detect_model_capabilities_from_show("custom:latest", show_data)
    assert thinking is False
    assert native_tools is False
