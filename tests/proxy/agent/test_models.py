from airecon.proxy.agent.models import AgentState


def test_agent_state_initializes_with_defaults():
    state = AgentState()
    assert state.conversation == []
    assert state.tool_history == []
    assert state.iteration == 0
    assert state.active_target is None


def test_agent_state_add_message():
    state = AgentState()
    state.add_message("user", "Hello World")

    assert len(state.conversation) == 1
    assert state.conversation[0] == {"role": "user", "content": "Hello World"}

    state.add_message("assistant", "Hi", tool_calls=[{"name": "test_tool"}])
    assert len(state.conversation) == 2
    assert state.conversation[1]["tool_calls"] == [{"name": "test_tool"}]


def test_agent_state_approaching_limit():
    state = AgentState(max_iterations=100)
    state.iteration = 96
    assert state.is_approaching_limit() is False

    state.iteration = 97
    assert state.is_approaching_limit() is True


def test_agent_state_truncate_conversation():
    state = AgentState()
    # Add many messages to force truncation
    for i in range(100):
        state.add_message("user", f"Message {i}")

    original_len = len(state.conversation)
    # The default budget for non-system messages limits keeping everything.
    state.truncate_conversation(max_messages=50)

    # After truncation, the actual number of messages should be bounded roughly to `max_messages` + separator
    assert len(state.conversation) < original_len
    # Since all messages are short strings, they are dropped instead of compressed text,
    # but dropped message triggers the separator adding logic.
    separator_exists = any(
        "older messages compressed/removed" in str(msg.get("content")) for msg in state.conversation)
    assert separator_exists


def test_agent_state_phase_objectives_and_status_updates():
    state = AgentState()
    defaults = [
        "Enumerate attack surface",
        "Confirm open ports",
    ]
    state.ensure_phase_objectives("RECON", defaults)
    # Re-adding defaults should not duplicate entries
    state.ensure_phase_objectives("RECON", defaults)

    recon_objs = [
        o for o in state.objective_queue
        if o.get("phase") == "RECON"
    ]
    assert len(recon_objs) == 2
    assert all(o.get("status") == "pending" for o in recon_objs)

    state.mark_objective("RECON", "Enumerate attack surface", "done")
    done_obj = next(
        o for o in state.objective_queue
        if o.get("phase") == "RECON"
        and o.get("title") == "Enumerate attack surface"
    )
    assert done_obj.get("status") == "done"


def test_agent_state_evidence_dedup_and_focus_context():
    state = AgentState()
    state.ensure_phase_objectives("ANALYSIS", ["Map technologies"])
    state.add_evidence(
        phase="ANALYSIS",
        source_tool="execute",
        summary="Detected CVE-2024-1234 in plugin banner",
        artifact="output/banner.txt",
        tags=["cve", "banner"],
    )
    # Duplicate evidence should be ignored
    state.add_evidence(
        phase="ANALYSIS",
        source_tool="execute",
        summary="Detected CVE-2024-1234 in plugin banner",
        artifact="output/banner.txt",
        tags=["cve", "banner"],
    )
    assert len(state.evidence_log) == 1

    context = state.build_focus_context("ANALYSIS")
    assert "OBJECTIVE FOCUS" in context
    assert "Map technologies" in context
    assert "CVE-2024-1234" in context
