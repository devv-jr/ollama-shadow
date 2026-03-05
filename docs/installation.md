# AIRecon Installation Guide

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Install Ollama](#2-install-ollama)
3. [Pull a Model](#3-pull-a-model)
4. [Install AIRecon](#4-install-airecon)
5. [Configure PATH](#5-configure-path)
6. [Build the Docker Sandbox](#6-build-the-docker-sandbox)
7. [Verify the Installation](#7-verify-the-installation)
8. [First Run](#8-first-run)
9. [Updating AIRecon](#9-updating-airecon)
10. [Remote Ollama Setup](#10-remote-ollama-setup)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. System Requirements

> **Model size requirement:** AIRecon requires a minimum of **30B parameters**. Models below 30B frequently fail to follow scope rules, hallucinate tool output, and produce incomplete function calls.

### Minimum viable (qwen3:30b-a3b — MoE)
| Component | Minimum |
|-----------|---------|
| OS | Linux, macOS, WSL2 on Windows |
| CPU | 8-core x86_64 |
| RAM | 24 GB |
| GPU VRAM | 16 GB NVIDIA |
| Storage | 40 GB free (model + Docker image + tools) |
| Python | 3.10+ |
| Docker | 24.0+ |
| Ollama | 0.6.1+ (required for extended thinking support) |

`qwen3:30b-a3b` is a Mixture-of-Experts model with lower active parameter count — it fits in 16 GB VRAM while retaining reasoning quality comparable to the full 32B.

### Recommended (qwen3:32b)
| Component | Recommended |
|-----------|------------|
| RAM | 32 GB+ |
| GPU VRAM | 20 GB NVIDIA |
| Storage | 60 GB free |

### High-end (qwen3.5:122b)
| Component | Required |
|-----------|---------|
| RAM | 80 GB+ |
| GPU VRAM | 48+ GB (multi-GPU or CPU+GPU offload) |

---

## 2. Install Ollama

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh

# Verify version — must be >= 0.6.1
ollama --version
```

Ensure Ollama is running as a service:

```bash
# Check status
systemctl status ollama

# Start if not running
sudo systemctl start ollama
# Or manually:
ollama serve &
```

---

## 3. Pull a Model

Pull the model you intend to use **before** starting AIRecon:

```bash
# Minimum viable — 30B MoE (~18 GB download, needs 16 GB VRAM)
ollama pull qwen3:30b-a3b

# Recommended — 32B (~20 GB download, needs 20 GB VRAM)
ollama pull qwen3:32b

# Best quality — requires high-end multi-GPU hardware
ollama pull qwen3.5:122b
```

Verify the model is available:

```bash
ollama list
# Should show: qwen3:32b   <hash>  <size>  <date>
```

> **Why not smaller models?** Models below 30B (e.g., `qwen3:14b`) frequently ignore scope rules, invent CVEs, produce malformed tool calls, and skip required PoC steps. They may work for simple isolated tasks but are unreliable for full engagement pipelines.

> **Performance tip:** For NVIDIA GPUs, set `OLLAMA_GPU_LAYERS=99` to maximize GPU offloading:
> ```bash
> # Add to /etc/systemd/system/ollama.service [Service] section:
> Environment="OLLAMA_GPU_LAYERS=99"
> systemctl daemon-reload && systemctl restart ollama
> ```

---

## 4. Install AIRecon

AIRecon uses [Poetry](https://python-poetry.org/) for dependency management and builds a Python wheel that is installed to your user path.

```bash
# 1. Clone the repository
git clone https://github.com/pikpikcu/airecon.git
cd airecon

# 2. Run the installer
./install.sh
```

### What `install.sh` does

1. **Checks for Poetry** — installs it via pip if missing
2. **Cleans previous installs** — removes old AIRecon versions to avoid conflicts
3. **Installs Python dependencies** — `poetry install` (reads `pyproject.toml`)
4. **Installs Playwright Chromium** — `poetry run playwright install chromium` (required for browser automation)
5. **Builds the wheel** — `poetry build` → creates `dist/airecon-*.whl`
6. **Installs to user site** — `pip install dist/airecon-*.whl --user` → binary at `~/.local/bin/airecon`

---

## 5. Configure PATH

The `airecon` command is installed to `~/.local/bin/`. If this is not in your PATH, the command will not be found.

```bash
# Check if it is already in PATH
which airecon

# If not found, add to your shell profile:

# For bash:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# For zsh:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify
airecon --version
```

---

## 6. Build the Docker Sandbox

The Docker sandbox is the Kali Linux execution environment where all shell commands run. You must build it before starting AIRecon.

```bash
cd airecon

# Build the sandbox image (takes 5–15 minutes on first build)
docker build -t airecon-sandbox airecon/containers/

# Verify the image exists
docker images | grep airecon-sandbox
```

> The sandbox includes: `nmap`, `naabu`, `masscan`, `subfinder`, `amass`, `httpx`, `nuclei`, `nikto`, `wapiti`, `ffuf`, `feroxbuster`, `sqlmap`, `dalfox`, `gau`, `waybackurls`, `katana`, `arjun`, full SecLists, FuzzDB, and 40+ more tools. It runs as user `pentester` with passwordless `sudo`.

If `docker_auto_build: true` is set in your config, AIRecon will attempt to build the image automatically at startup if it is not found. Manual build is more reliable.

---

## 7. Verify the Installation

Run this checklist after installing:

```bash
# 1. Check AIRecon version
airecon --version

# 2. Check Ollama is running and model is available
ollama list

# 3. Check Docker image
docker images | grep airecon-sandbox

# 4. Test Playwright (should open and close Chromium silently)
python3 -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(); b.close(); p.stop(); print('Playwright OK')"

# 5. Check config file location
cat ~/.airecon/config.json 2>/dev/null || echo "Will be created on first run"
```

---

## 8. First Run

```bash
# Navigate to a working directory (workspace/ will be created here)
cd ~/pentest-projects/

# Start the TUI
airecon start
```

On first run:
- `~/.airecon/config.json` is created with default values
- The `workspace/` directory is created in your current working directory
- The Docker sandbox container is started

**Set the correct model in config before starting:**

```bash
# Edit config
nano ~/.airecon/config.json

# Change "ollama_model" to match what you pulled, e.g.:
# "ollama_model": "qwen3:32b"
# "ollama_model": "qwen3:30b-a3b"
# "ollama_model": "qwen3.5:122b"
```

See [Configuration Reference](configuration.md) for all options.

---

## 9. Updating AIRecon

```bash
cd airecon

# Pull latest changes
git pull

# Re-run the installer
./install.sh
```

The installer automatically cleans the previous version before reinstalling.

---

## 10. Remote Ollama Setup

If your Ollama instance runs on a separate machine (e.g., a GPU server):

**On the Ollama server:**
```bash
# Bind Ollama to all interfaces
OLLAMA_HOST=0.0.0.0 ollama serve

# Or set permanently in the systemd service:
# Environment="OLLAMA_HOST=0.0.0.0"
```

**In `~/.airecon/config.json` on your workstation:**
```json
{
    "ollama_url": "http://<server-ip>:11434",
    "ollama_model": "qwen3:32b"
}
```

Make sure port 11434 is open in the server's firewall.

---

## 11. Troubleshooting

### `airecon: command not found`
`~/.local/bin` is not in PATH. Follow [Step 5](#5-configure-path).

### `ollama: connection refused`
Ollama is not running. Start it: `ollama serve` or `sudo systemctl start ollama`.

### `docker: Cannot connect to the Docker daemon`
Docker daemon is not running: `sudo systemctl start docker`.

### `airecon-sandbox` image not found at startup
Build manually: `docker build -t airecon-sandbox airecon/containers/`

### `Model not found` / model name mismatch
Run `ollama list` and copy the exact model name (including tag) into `ollama_model` in config.

### `Ollama returned HTML error page` / server crashed

**Root cause:** Ollama ran out of VRAM and crashed. When this happens, Ollama's HTTP server returns an HTML error page instead of a JSON response, which AIRecon cannot parse.

This is the most common error on sessions with long context history or when running large models near VRAM limits.

**Why it happens:**
- The KV cache (conversation history) grows with each iteration — a 500-iteration session can consume 2–4× more VRAM than the initial load
- `ollama_num_ctx: 65536` with a 32B model requires ~6–8 GB VRAM just for the KV cache, on top of model weights
- Spawning parallel agents (`run_parallel_agents`) doubles or triples VRAM usage simultaneously

**Fix in order of preference:**

**1. Restart Ollama immediately (quick fix):**
```bash
sudo systemctl restart ollama
# or if running manually:
pkill ollama && ollama serve &
```

**2. Reduce context window (permanent fix):**
```json
{
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384
}
```

**3. Reduce max output tokens:**
```json
{
    "ollama_num_predict": 8192
}
```

**4. Shorten model keep-alive to free VRAM between sessions:**
```json
{
    "ollama_keep_alive": "5m"
}
```

**5. Limit parallel agent concurrency** — avoid `run_parallel_agents` if VRAM is near the limit. Use `spawn_agent` (single specialist) instead.

**Recommended safe config for 16–20 GB VRAM:**
```json
{
    "ollama_model": "qwen3:32b",
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384,
    "ollama_num_predict": 8192,
    "ollama_keep_alive": "10m"
}
```

> The agent uses automatic context compression every 15 iterations, so reducing `ollama_num_ctx` has minimal impact on long session quality.

### Context length error / out of memory (VRAM)
Lower `ollama_num_ctx` in config:
```json
"ollama_num_ctx": 32768
```
Or use a smaller model. See the `Ollama returned HTML error page` section above for a complete diagnosis.

### Playwright error: `executable doesn't exist`
Reinstall Playwright browsers:
```bash
cd airecon
poetry run playwright install chromium
```

### `Connection timeout` to Ollama during long scans
Increase `ollama_timeout` in config (default 1900s should be sufficient for most models):
```json
"ollama_timeout": 3600.0
```

### Poetry install fails with dependency conflicts
```bash
# Clean Poetry environment and retry
poetry env remove python3
poetry install
```
