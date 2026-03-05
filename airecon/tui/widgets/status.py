"""Status bar widget: connection indicators, model info, tokens, skills, caido."""

from __future__ import annotations

from textual.widgets import Label
from textual.containers import Horizontal
from textual.reactive import reactive


class StatusBar(Horizontal):
    """Bottom status bar showing services, tokens, skills, and caido status."""

    DEFAULT_CSS = ""  # Defer to styles.tcss

    ollama_status = reactive("offline")
    docker_status = reactive("offline")
    model_name = reactive("—")
    token_count = reactive(0)
    token_limit = reactive(65536)
    exec_used = reactive(0)
    subagents_spawned = reactive(0)
    skills_used = reactive("")  # CSV of current skills being used
    caido_active = reactive(False)
    caido_findings = reactive(0)

    def compose(self):
        yield Label(id="status-text")

    def on_mount(self) -> None:
        self._update_display()

    def _get_status_text(self) -> str:
        # Service indicators
        ollama_dot = "●" if self.ollama_status == "online" else "○"
        ollama_color = "#00d4aa" if self.ollama_status == "online" else "#ef4444"

        docker_dot = "●" if self.docker_status == "online" else "○"
        docker_color = "#00d4aa" if self.docker_status == "online" else "#ef4444"

        # Token usage: format as thousands (e.g., 12.450k)
        token_thousands = self.token_count / 1000.0
        
        # Color based on token usage (not ratio): green < 20k, orange 20-50k, red > 50k
        if self.token_count < 20000:
            token_color = "#00d4aa"  # Green: safe
        elif self.token_count < 50000:
            token_color = "#f59e0b"  # Orange: caution
        else:
            token_color = "#ef4444"  # Red: critical
        
        # Display tokens in thousands format
        token_part = f"  │ [#8b949e]Token:[/] [{token_color}]{token_thousands:.3f}k[/]"

        # Skills used
        skills_part = ""
        if self.skills_used:
            # Truncate long skill list
            skills_display = self.skills_used[:40]
            if len(self.skills_used) > 40:
                skills_display += "…"
            skills_part = f"  │ [#8b949e]Skills:[/] [#818cf8]{skills_display}[/]"

        # Caido status
        caido_part = ""
        if self.caido_active:
            caido_part = f"  │ [#ec4899]🔴 Caido[/] [#f87171]{self.caido_findings}[/] findings"

        # Agents/Exec stats
        subagent_part = (
            f"  │ [#8b949e]Agents:[/] [#a78bfa]{self.subagents_spawned}[/]"
            if self.subagents_spawned > 0 else ""
        )

        return (
            f" [{ollama_color}]{ollama_dot}[/] Ollama  "
            f"[{docker_color}]{docker_dot}[/] Docker  "
            f"│ [#8b949e]Model:[/] [#00d4aa]{self.model_name}[/]"
            f"{token_part}"
            f"{skills_part}"
            f"{caido_part}"
            f"  │ [#8b949e]Exec:[/] [#f59e0b]{self.exec_used}[/]"
            f"{subagent_part}  "
            f"│ [#484f58]Ctrl+C quit · Ctrl+L clear[/]"
        )

    def watch_ollama_status(self, _) -> None: self._update_display()
    def watch_docker_status(self, _) -> None: self._update_display()
    def watch_model_name(self, _) -> None: self._update_display()
    def watch_token_count(self, _) -> None: self._update_display()
    def watch_token_limit(self, _) -> None: self._update_display()
    def watch_exec_used(self, _) -> None: self._update_display()
    def watch_subagents_spawned(self, _) -> None: self._update_display()
    def watch_skills_used(self, _) -> None: self._update_display()
    def watch_caido_active(self, _) -> None: self._update_display()
    def watch_caido_findings(self, _) -> None: self._update_display()

    def _update_display(self) -> None:
        try:
            self.query_one(
                "#status-text",
                Label).update(
                self._get_status_text())
        except Exception:
            pass

    def set_status(
        self,
        ollama: str | None = None,
        docker: str | None = None,
        model: str | None = None,
        tokens: int | None = None,
        token_limit: int | None = None,
        tools: int | None = None,
        exec_used: int | None = None,
        subagents: int | None = None,
        skills: str | None = None,
        caido_active: bool | None = None,
        caido_findings: int | None = None,
    ) -> None:
        """Update status bar with new information.
        
        Args:
            ollama: Status "online"/"offline"
            docker: Status "online"/"offline"
            model: Model name (e.g., "qwen:122b")
            tokens: Current token count used
            token_limit: Max token limit
            tools: Deprecated (kept for compatibility)
            exec_used: Number of execute() calls made
            subagents: Number of spawned subagents
            skills: Comma-separated skill names being used
            caido_active: Whether Caido is currently active
            caido_findings: Number of findings from Caido
        """
        if ollama is not None:
            self.ollama_status = ollama
        if docker is not None:
            self.docker_status = docker
        if model is not None:
            self.model_name = model
        if tokens is not None:
            self.token_count = tokens
        if token_limit is not None:
            self.token_limit = token_limit
        if exec_used is not None:
            self.exec_used = exec_used
        if subagents is not None:
            self.subagents_spawned = subagents
        if skills is not None:
            self.skills_used = skills
        if caido_active is not None:
            self.caido_active = caido_active
        if caido_findings is not None:
            self.caido_findings = caido_findings
