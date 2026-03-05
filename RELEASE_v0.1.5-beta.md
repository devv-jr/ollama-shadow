# AIRecon v0.1.5-beta Release Notes

## 🚀 What's New in v0.1.5-beta

Welcome to the **v0.1.5-beta** release of AIRecon! This update focuses on core stability, race condition fixes, and introducing a comprehensive automated testing suite.

### 🛡️ Core Fixes & Stability
- **LLM Context & Crash Fixes:** Resolved a critical `unhashable list` crash by properly unpacking the tuple return value from `auto_load_skills_for_message` (#5159ffd).
- **Graceful Degradation:** Fuzzer now degrades gracefully with warnings when `fuzzer_data.json` is missing, preventing hard crashes (#5f05610).
- **Logger Fixes:** Corrected missing logger imports in the Correlation Agent (#5f05610).
- **Browser Race Condition:** Fixed a critical race condition in the Playwright browser's event loop initialization using `threading.Event().wait()` timeouts (#5f05610).
- **Docker & Ollama Fixes:** Resolved race conditions in `docker force_stop` and Ollama model detection logic (#c5a89a5).

### 🧪 Enhancements & Testing
- **Comprehensive Unit Tests:** Implemented a full `pytest` unit testing suite covering `proxy`, `agent`, and `tui` modules, completely automating regression testing (#d13cbf4).
- **Live Output Initialization:** Fixed live output display and removed unused reload overrides (#59fda6c).
- **Repository Hygiene:** Cleaned up version control by ignoring `.vscode/` and `__pycache__/` (#87b8a37, #9114914).

---

**Full Changelog**: https://github.com/pikpikcu/airecon/compare/v0.1.4...v0.1.5-beta
