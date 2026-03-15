<h1 align="center">
  <img src="images/ollama.png" alt="Ollama Shadow" width="220">
</h1>

<h4 align="center">Cloud-Powered Autonomous Penetration Testing Agent</h4>

<p align="center">
  <img src="https://img.shields.io/badge/language-python-green.svg">
  <img src="https://img.shields.io/badge/version-v0.1.0-green.svg">
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg">
  <img src="https://img.shields.io/badge/LLM-Ollama%20Cloud-orange.svg">
  <a href="https://github.com/YOUR-USERNAME/ollama-shadow/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/LICENSE-MIT-red.svg">
  </a>
</p>

**Ollama Shadow** is an autonomous pentesting agent that combines **Ollama Cloud** (massive 70B–480B+ models with no local VRAM limits) with a **Kali Linux Docker sandbox**, native **Caido proxy** integration, a structured **RECON → ANALYSIS → EXPLOIT → REPORT** pipeline, and a real-time **Textual TUI** interface.

It runs advanced cloud-based reasoning while keeping all tool execution and exploit running 100% local and secure.

![Screenshot](images/ollama-shadow-demo.png)
*(TUI screenshot in action — replace with your own)*

---

## Why Ollama Shadow?

Agents built on commercial APIs (GPT-4o, Claude 4, Gemini 2.5) get expensive in recursive pentest workflows (thousands of calls per session). Fully local setups are bottlenecked by model size (a Quadro T2000 4GB only runs ~3–8B models comfortably).

**Ollama Shadow** solves both problems:
- Reasoning via **massive cloud models** (qwen3-coder:480b-cloud, gpt-oss:120b-cloud, etc.)
- Tool execution (nmap, nuclei, metasploit…) runs on your local machine
- Privacy: prompts and targets are never sent without your explicit control

| Feature                        | Ollama Shadow            | Pure cloud agents | 100% local agents  |
|--------------------------------|--------------------------|-------------------|--------------------|
| Models >70B without a GPU      | **Yes (Ollama Cloud)**   | Yes               | No                 |
| API key required               | Only for cloud           | Yes               | No                 |
| Target data sent to cloud      | Prompts only (optional)  | Yes               | No                 |
| Works offline                  | Local fallback           | No                | Yes                |
| Native Caido integration       | **Yes**                  | No                | Yes                |
| Cost per long session          | Low (~$20/mo Pro)        | High              | $0 (hardware only) |

- **Hybrid privacy** — Choose cloud for intelligence, local for sensitive execution
- **Caido built-in** — 5 native tools: list, replay, fuzz (§FUZZ§), findings, scope
- **Full stack** — Kali sandbox + browser automation + custom fuzzer + Schemathesis + Semgrep
- **Skill library** — 50+ predefined skills (vuln classes, tool mappings)

---

## Pipeline

```
RECON → ANALYSIS → EXPLOIT → REPORT
```

Guided phases with automatic transition criteria. Checkpoints every 5–15 iterations (phase eval, self-eval, context compression).

---

## Model Requirements (Cloud-first)

Ollama Shadow prioritizes cloud models with tool-calling and extended reasoning (`<think>` blocks).

| Model                        | Pull command / tag                     | Local VRAM | Notes                              |
|------------------------------|----------------------------------------|------------|------------------------------------|
| **qwen3-coder:480b-cloud**   | `ollama pull qwen3-coder:480b-cloud`   | 0 GB       | **Best for coding/exploits**       |
| **gpt-oss:120b-cloud**       | `ollama pull gpt-oss:120b-cloud`       | 0 GB       | Excellent general reasoning        |
| **qwen3.5:122b-cloud**       | `ollama pull qwen3.5:122b-cloud`       | 0 GB       | Multimodal + tools                 |
| qwen3:32b (local fallback)   | `ollama pull qwen3:32b`                | ~20 GB     | If not using cloud                 |

**Recommended minimum (cloud):** any `-cloud` model with tool support.
Models under 30B local tend to hallucinate CVEs or ignore scope constraints.

---

## Installation

**Requirements:** Python 3.12+, Docker, Poetry, Ollama CLI, and an account at [ollama.com](https://ollama.com)

```bash
git clone https://github.com/devv-jr/ollama-shadow.git
cd ollama-shadow
./install.sh
```

The script installs dependencies, Playwright, and builds the binary at `~/.local/bin/ollama-shadow`.

```bash
# Add to PATH if needed
export PATH="$HOME/.local/bin:$PATH"
source ~/.bashrc   # or ~/.zshrc

ollama-shadow --version
```

**Ollama Cloud setup (required for cloud mode):**

1. Create an account → [https://ollama.com](https://ollama.com)
2. Generate an API Key → [https://ollama.com/settings/keys](https://ollama.com/settings/keys)
3. Export it:

```bash
export OLLAMA_API_KEY=your-api-key-here
```

---

## Configuration

Config file: `~/.ollama-shadow/config.json` (auto-generated on first run)

```json
{
  "ollama_host": "https://ollama.com/api",
  "ollama_model": "qwen3-coder:480b-cloud",
  "ollama_api_key": "your-api-key (or use environment variable)",
  "ollama_timeout": 2400.0,
  "ollama_num_ctx": 131072,
  "ollama_temperature": 0.15,
  "proxy_port": 3000,
  "command_timeout": 900.0,
  "docker_auto_build": true,
  "agent_max_tool_iterations": 800,
  "allow_destructive_testing": false
}
```

| Key                          | Default                    | Notes                                               |
|------------------------------|----------------------------|-----------------------------------------------------|
| `ollama_host`                | `https://ollama.com/api`   | Change to `http://localhost:11434` for local mode   |
| `ollama_model`               | `qwen3-coder:480b-cloud`   | Use the `-cloud` suffix for cloud models            |
| `ollama_temperature`         | `0.15`                     | 0.1–0.2 recommended to reduce hallucinations        |
| `allow_destructive_testing`  | `false`                    | Unlocks aggressive exploit chains (use with care)   |

---

## Usage

```bash
ollama-shadow start                                              # Launch TUI (cloud by default)
ollama-shadow start --model gpt-oss:120b-cloud --target example.com
ollama-shadow start --session <id>                              # Resume a session
```

**Example prompts:**

```
full recon on example.com
pentest https://api.target.com
find subdomains and scan ports on 10.10.10.10
test XSS on https://target.com/search?q=
test SQLi on login form parameter: username
spawn XSS specialist + SQLi specialist in parallel
use Caido to fuzz Authorization header in request #42
```

---

## Workspace & Sessions

```
workspace/<target>/
├── output/          # Raw tool output (nmap, nuclei…)
├── tools/           # AI-generated exploit scripts
└── vulnerabilities/ # Verified vulnerability reports (.md)
```

Sessions are stored at `~/.ollama-shadow/sessions/<id>.json` — persists subdomains, verified vulns (Jaccard dedup), auth tokens, and completed phases.

---

## Troubleshooting

- **Cloud: "No model found"** → Verify `OLLAMA_API_KEY` and the `-cloud` suffix in the model name.
- **OOM / slowness** → Lower `ollama_num_ctx` to `32768` or switch to a smaller model.
- **Docker build failure** → Run `docker build -t ollama-shadow-sandbox containers/kali/` manually.

---

## Additional Documentation

- [Features](docs/features.md)
- [Full Configuration Reference](docs/configuration.md)
- [Tools & Skills](docs/tools.md)
- [Adding Custom Skills](docs/custom-skills.md)

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Disclaimer

Ollama Shadow is intended for educational purposes, ethical hacking, and authorized security assessments only. Any use against systems without explicit written permission is solely the responsibility of the user. Do not use this tool on networks or targets you do not own or have authorization to test.

---

⭐ Star the repo if you find it useful, and feel free to contribute! 🔥
