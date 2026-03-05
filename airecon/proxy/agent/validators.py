from __future__ import annotations

from typing import Any


class _ValidatorMixin:

    _VALID_BROWSER_ACTIONS = frozenset({
        "launch", "goto", "click", "type", "scroll_down", "scroll_up", "back",
        "forward", "new_tab", "switch_tab", "close_tab", "wait", "execute_js",
        "double_click", "hover", "press_key", "save_pdf", "get_console_logs",
        "get_network_logs", "view_source", "close", "list_tabs",
    })

    def _validate_tool_args(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, str | None]:
        if tool_name == "execute":
            cmd = arguments.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                return False, "'command' must be a non-empty string."
            if len(cmd) > 20_000:
                return False, f"'command' is too long ({len(cmd)} chars). Split into smaller calls."

        elif tool_name == "browser_action":
            action = arguments.get("action", "")
            if action not in self._VALID_BROWSER_ACTIONS:
                return False, (
                    f"Invalid browser action '{action}'. "
                    f"Valid actions: {sorted(self._VALID_BROWSER_ACTIONS)}"
                )
            if action in ("goto", "new_tab") and not arguments.get(
                    "url", "").strip():
                return False, f"browser_action '{action}' requires a non-empty 'url'."
            if action == "click" and not arguments.get(
                    "coordinate", "").strip():
                return False, "browser_action 'click' requires 'coordinate' (format: 'x,y')."
            if action == "type" and arguments.get("text") is None:
                return False, "browser_action 'type' requires a 'text' argument."
            if action == "switch_tab" and not arguments.get(
                    "tab_id", "").strip():
                return False, "browser_action 'switch_tab' requires 'tab_id'."
            if action == "press_key" and not arguments.get("key", "").strip():
                return False, "browser_action 'press_key' requires 'key'."

        elif tool_name == "web_search":
            if not arguments.get("query", "").strip():
                return False, "'query' must be a non-empty string."

        elif tool_name == "create_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."
            if "content" not in arguments:
                return False, "'content' argument is required."
            # Block writing security reports as markdown files — must use
            # create_vulnerability_report
            path_lower = arguments["path"].strip().lower()
            _REPORT_NAMES = (
                "final_report", "report", "vuln", "vulnerability", "finding",
                "assessment", "security_report", "pentest_report", "summary_report",
            )
            if path_lower.endswith(".md") and any(
                    r in path_lower for r in _REPORT_NAMES):
                return False, (
                    "BLOCKED: Writing vulnerability findings to a markdown file is FORBIDDEN. "
                    "Use create_vulnerability_report for each confirmed finding. "
                    "create_file is for scripts, wordlists, config, and tool output only — "
                    "never for security reports."
                )

        elif tool_name == "read_file":
            if not arguments.get("path", "").strip():
                return False, "'path' must be a non-empty string."
            if "offset" in arguments:
                try:
                    if int(arguments["offset"]) < 0:
                        return False, "'offset' must be >= 0."
                except (TypeError, ValueError):
                    return False, "'offset' must be an integer."
            if "limit" in arguments:
                try:
                    lim = int(arguments["limit"])
                    if lim < 1 or lim > 5000:
                        return False, "'limit' must be between 1 and 5000."
                except (TypeError, ValueError):
                    return False, "'limit' must be an integer."

        elif tool_name == "list_files":
            pass  # path is optional; defaults to target root

        elif tool_name == "create_vulnerability_report":
            poc_code = arguments.get("poc_script_code", "").strip()
            poc_desc = arguments.get("poc_description", "").strip()
            title = arguments.get("title", "").strip()
            technical = arguments.get("technical_analysis", "").strip()
            is_ctf = bool(arguments.get("flag", "").strip())

            POC_CODE_INDICATORS = (
                "import ", "requests.", "curl ", "http", "def ", "response",
                "payload", "exploit", "fetch(", "<?php", "<script", "burp",
                "#!/", "python", "urllib",
            )
            if not poc_code:
                return False, (
                    "REPORT REJECTED: 'poc_script_code' is empty. "
                    "Provide actual exploit code or a curl command demonstrating the vulnerability."
                )
            if len(poc_code) < 50:
                return False, (
                    f"REPORT REJECTED: 'poc_script_code' is too short ({
                        len(poc_code)} chars). "
                    "Provide a real exploit: Python script, curl command, or HTTP request."
                )
            if not any(ind in poc_code.lower() for ind in POC_CODE_INDICATORS):
                return False, (
                    "REPORT REJECTED: 'poc_script_code' does not look like code. "
                    "It must contain executable commands (curl, Python requests, HTTP request, etc.)."
                )
            if not poc_desc or len(poc_desc) < 80:
                return False, (
                    f"REPORT REJECTED: 'poc_description' is too short ({
                        len(poc_desc)} chars). "
                    "Provide step-by-step reproduction with specific URLs, parameters, and observed behavior."
                )
            # technical_analysis is only mandatory for full reports, not CTF
            if not is_ctf and (not technical or len(technical) < 80):
                return False, (
                    f"REPORT REJECTED: 'technical_analysis' is too short ({
                        len(technical)} chars). "
                    "Explain the root cause with specific technical details."
                )
            GENERIC_TITLES = (
                "vulnerability found", "security issue", "bug found", "potential",
                "possible", "issue detected", "security bug",
            )
            if any(g in title.lower()
                   for g in GENERIC_TITLES) or len(title) < 15:
                return False, (
                    f"REPORT REJECTED: Title '{title}' is too vague. "
                    "Use a specific title like 'SQL Injection in /api/login username parameter'."
                )
            # Reject unverified/speculative findings — all reports must be
            # confirmed
            UNVERIFIED_PHRASES = (
                "further verification needed", "needs verification", "needs to be verified",
                "may be vulnerable", "could be vulnerable", "appears to be vulnerable",
                "potentially vulnerable", "might be vulnerable", "possible vulnerability",
                "note:", "unconfirmed", "not confirmed", "could not confirm",
                "needs more testing", "requires further", "needs further",
            )
            combined_text = (poc_desc + " " + technical).lower()
            for phrase in UNVERIFIED_PHRASES:
                if phrase in combined_text:
                    return False, (
                        f"REPORT REJECTED: Report contains unverified language: '{phrase}'. "
                        "Only submit findings you have CONFIRMED by observing actual exploitation impact. "
                        "Do not submit speculative or unverified findings."
                    )
            # poc_script_code must reference a real URL (not a generic
            # template)
            if "http" not in poc_code.lower() and "curl" not in poc_code.lower():
                return False, (
                    "REPORT REJECTED: 'poc_script_code' must include the actual target URL. "
                    "Show the real HTTP request that demonstrates the vulnerability."
                )
            # HTTP evidence check only for full reports, not CTF
            if not is_ctf:
                # poc_description must contain observed HTTP response evidence
                # (a status code like 200, 301, 403 proves the request was actually made)
                import re as _re
                _HTTP_EVIDENCE = _re.compile(
                    r"(http\s+[2345]\d{2}|status[:\s]+[2345]\d{2}|code\s+[2345]\d{2}|"
                    r"\b[2345]\d{2}\s+(ok|found|forbidden|redirect|not found|created|"
                    r"accepted|no content|moved|unauthorized|bad request|internal server error|"
                    r"forbidden|unauthorized|forbidden)\b|"
                    r"response[:\s]+[2345]\d{2}|→\s*[2345]\d{2}|"
                    r"\[[2345]\d{2}\]|\([2345]\d{2}\)|\{[2345]\d{2}\}|"
                    r"returned\s+[2345]\d{2}|returns\s+[2345]\d{2}|got\s+[2345]\d{2}|"
                    r"observed[:\s]+[2345]\d{2}|status\s*[2345]\d{2})",
                    _re.IGNORECASE,
                )
                if not _HTTP_EVIDENCE.search(poc_desc):
                    return False, (
                        "REPORT REJECTED: 'poc_description' must include actual HTTP response evidence. "
                        "Show the real status code and response data you observed, e.g.: "
                        "'GET /api/data → HTTP 200, response contained {user records}'. "
                        "A 301 redirect alone, or 'endpoint exists', is not sufficient — show what data/access was obtained."
                    )

        return True, None
