# Ollama Shadow Configuration Reference

## Table of Contents

1. [Config File Location](#1-config-file-location)
2. [Full Config Reference](#2-full-config-reference)
3. [Ollama Settings](#3-ollama-settings)
4. [Agent Behavior](#4-agent-behavior)
5. [Docker Sandbox](#5-docker-sandbox)
6. [Server Settings](#6-server-settings)
7. [Safety Settings](#7-safety-settings)
8. [Browser Settings](#8-browser-settings)
9. [Search Settings](#9-search-settings)
10. [Session Settings](#10-session-settings)
11. [Environment Variable Overrides](#11-environment-variable-overrides)
12. [Configuration Presets](#12-configuration-presets)

---

## 1. Config File Location

| Path | Purpose |
|------|---------|
| `~/.ollama-shadow/config.json` | Primary config (auto-created on first run) |

On first run, if no config file exists, Ollama Shadow writes the defaults to `~/.ollama-shadow/config.json`. Edit this file to customize behavior.

```bash
# View current config
cat ~/.ollama-shadow/config.json

# Edit
nano ~/.ollama-shadow/config.json
# or
code ~/.ollama-shadow/config.json
```

---

## 2. Full Config Reference

```json
{
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_model": "qwen3.5:122b",
    "ollama_timeout": 1900.0,
    "ollama_num_ctx": 65536,
    "ollama_num_ctx_small": 32768,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 16384,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "ollama_keep_alive": "30m",
    "proxy_host": "127.0.0.1",
    "proxy_port": 3000,
    "command_timeout": 900.0,
    "docker_image": "ollama-shadow-sandbox",
    "docker_auto_build": true,
    "tool_response_role": "tool",
    "deep_recon_autostart": true,
    "agent_max_tool_iterations": 500,
    "agent_repeat_tool_call_limit": 2,
    "agent_missing_tool_retry_limit": 2,
    "agent_plan_revision_interval": 30,
    "allow_destructive_testing": true,
    "browser_page_load_delay": 1.0,
    "searxng_url": "http://localhost:8080",
    "searxng_engines": "google,bing,duckduckgo,brave,google_news,github,stackoverflow",
    "vuln_similarity_threshold": 0.7
}
```

---

## 3. Ollama Settings

### `ollama_url`
**Type:** string | **Default:** `"http://127.0.0.1:11434"`

The HTTP endpoint of your Ollama instance. Change this if Ollama runs on a different host or port.

```json
// Local default
"ollama_url": "http://127.0.0.1:11434"

// Remote GPU server
"ollama_url": "http://192.168.1.100:11434"

// Custom port
"ollama_url": "http://127.0.0.1:3003"
```

---

### `ollama_model`
**Type:** string | **Default:** `"qwen3.5:122b"`

The model name exactly as shown in `ollama list`. Must include the tag.

```json
// Minimum recommended (30B — anything below 30B is unreliable)
"ollama_model": "qwen3:32b"

// Lower VRAM option (MoE — 30B active params)
"ollama_model": "qwen3:30b-a3b"

// High-end (best quality)
"ollama_model": "qwen3.5:122b"
```

> **Important:** The name must match exactly. `qwen3:32b` and `qwen3:latest` are different entries. Run `ollama list` to see exact names.
>
> **Minimum size:** 30B parameters. Models below 30B frequently fail to follow scope rules, hallucinate tool output, and produce incomplete function calls. `qwen3:14b` is NOT recommended for real engagements.

---

### `ollama_temperature`
**Type:** float | **Default:** `0.15`

Controls output randomness. This is the single most impactful setting for agent reliability.

| Value | Effect on Ollama Shadow |
|-------|------------------|
| `0.0` | Fully deterministic. Same input = same output every time. |
| `0.1`–`0.15` | **Recommended.** Strict instruction following. Minimal hallucination. Model respects scope rules. |
| `0.2` | Slightly more adaptive. Useful if model feels repetitive when stuck on a problem. |
| `0.3` | Noticeable creativity. Still acceptable for tool-calling agents. |
| `0.5–0.6` | High risk of scope creep (model "improvises" extra steps). Chain creep becomes frequent. |
| `> 0.7` | Model frequently ignores scope rules, invents tool output, hallucinates CVEs. Not recommended. |

**Why low temperature matters for security agents:**

The model's job is to follow strict protocols (task scoping, CVSS scoring, PoC requirements) rather than to be creative. Higher temperature increases the chance the model "reasons itself" into skipping rules.

For reasoning models (qwen3 with `ollama_enable_thinking: true`), the `<think>` phase already handles analytical depth internally. The output temperature can therefore be very low (0.15) without losing quality.

---

### `ollama_num_ctx`
**Type:** int | **Default:** `65536` (64K tokens)

Context window size in tokens. Larger = more history visible to the model = better continuity, but requires more VRAM.

| Value | VRAM impact | Use case |
|-------|-------------|----------|
| `8192` | Minimal | Quick tests, very limited VRAM |
| `32768` | Moderate | General use with 8–16 GB VRAM |
| `65536` | High | **Default** — deep recon sessions, 16+ GB VRAM |
| `131072` | Very high | Extended sessions, 32+ GB VRAM |

> Reduce this first if you get out-of-memory errors. The agent uses automatic conversation truncation (every 15 iterations) to manage context, so reducing this is safe.

---

### `ollama_num_ctx_small`
**Type:** int | **Default:** `32768`

A smaller context window used for lightweight operations (e.g., skill reads, status queries) that don't require the full context. Reduces VRAM pressure during intermediate operations.

---

### `ollama_num_predict`
**Type:** int | **Default:** `16384`

Maximum number of tokens the model can generate in a single response. 16384 ≈ ~12,000 words — enough for complex tool-calling responses with reasoning.

Reduce to `4096` if responses feel slow and you don't need long output. Increase for very long exploitation write-ups.

---

### `ollama_timeout`
**Type:** float | **Default:** `1900.0` seconds

How long to wait for a streaming response before giving up. Default is ~31 minutes — appropriate for large models on CPU or GPU with high context.

```json
// For fast GPU inference
"ollama_timeout": 300.0

// For very large models (122B) on CPU
"ollama_timeout": 7200.0
```

---

### `ollama_enable_thinking`
**Type:** bool | **Default:** `true`

Enables the `think=true` parameter when calling Ollama, which activates extended reasoning (`<think>` blocks) for supported models.

| Model type | Recommended setting |
|------------|-------------------|
| Reasoning model (qwen3, deepseek-r1) | `true` |
| Standard/chat model (llama3, mistral) | `false` |

When enabled, the TUI shows the model's internal reasoning process in the thinking panel, separate from the final output. This is very useful for understanding why the agent made a specific decision.

---

## 4. Agent Behavior

### `deep_recon_autostart`
**Type:** bool | **Default:** `true`

When `true`, if the user inputs **only** a bare domain name (e.g., just `example.com` with nothing else), Ollama Shadow automatically expands it into a full deep recon prompt:

```
Perform a comprehensive full deep recon and vulnerability scan on example.com. Use all available tools.
```

Set to `false` if you want the agent to treat bare domain input as "just set the target, wait for further instructions."

```json
// Auto-expand bare domain to full recon
"deep_recon_autostart": true

// Treat bare domain as target selection only
"deep_recon_autostart": false
```

---

### `agent_max_tool_iterations`
**Type:** int | **Default:** `500`

Safety limit on the number of tool call cycles per user message. Prevents infinite loops.

For full recon engagements on complex targets, 500 iterations is the minimum. For specific tasks, the agent typically finishes in 3–20 iterations.

```json
// Tight limit for specific tasks only
"agent_max_tool_iterations": 100

// Extended for deep recon
"agent_max_tool_iterations": 1000
```

---

### `agent_repeat_tool_call_limit`
**Type:** int | **Default:** `2`

How many times the **exact same tool + identical arguments** combination is allowed before being blocked as a duplicate.

The agent maintains a count per (tool, arguments) pair per session. When the count reaches this limit, the tool call is rejected with an error message telling the agent to try something different.

```json
// Strict: block after first repeat
"agent_repeat_tool_call_limit": 1

// Relaxed: allow up to 3 identical calls
"agent_repeat_tool_call_limit": 3
```

> Note: This only blocks **identical** calls (same tool + same arguments). Different arguments or a different tool on the same target are not affected.

---

### `agent_missing_tool_retry_limit`
**Type:** int | **Default:** `2`

How many consecutive times the agent may call a tool that does not exist before the session is aborted.

When the agent hallucinates a tool name (e.g., calls `run_nmap` instead of `execute`), it receives an error listing the valid tools. If it continues calling non-existent tools this many times in a row, the session stops to prevent an infinite error loop.

---

### `tool_response_role`
**Type:** string | **Default:** `"tool"`

The message role used when returning tool results to the LLM in the conversation history.

| Value | When to use |
|-------|-------------|
| `"tool"` | Models that support the Ollama `tool` message role (qwen3, most modern models) |
| `"user"` | Fallback for older models that don't understand the tool role |

Most models work correctly with `"tool"`. If you see the model failing to parse tool results, try `"user"`.

---

## 5. Docker Sandbox

### `docker_image`
**Type:** string | **Default:** `"ollama-shadow-sandbox"`

The name of the Docker image used as the execution sandbox. Must be built before first use.

```bash
docker build -t ollama-shadow-sandbox ollama-shadow/containers/
```

If you build with a different tag, update this setting accordingly.

---

### `docker_auto_build`
**Type:** bool | **Default:** `true`

If `true`, Ollama Shadow attempts to build the Docker image automatically at startup if it is not found. This can fail in restricted environments. Manual build is more reliable.

---

### `command_timeout`
**Type:** float | **Default:** `900.0` seconds (15 minutes)

Maximum time a single shell command may run inside the Docker container before being killed.

```json
// Quick scans only
"command_timeout": 120.0

// Allow long-running tools (masscan, full nmap, large sqlmap)
"command_timeout": 1800.0
```

Nuclei, sqlmap, and full nmap scans can easily take > 10 minutes on large target lists. Increase this if commands are being killed prematurely.

---

## 6. Server Settings

### `proxy_host` / `proxy_port`
**Type:** string / int | **Defaults:** `"127.0.0.1"` / `3000`

The host and port for the internal FastAPI server that bridges the TUI and the agent loop via SSE (Server-Sent Events).

Only change these if port 3000 is already in use on your machine:

```json
"proxy_host": "127.0.0.1",
"proxy_port": 3001
```

---

## 7. Safety Settings

### `allow_destructive_testing`
**Type:** bool | **Default:** `true`

When `true`, modifies the system prompt to authorize destructive/aggressive testing:
- Changes "non-destructive penetration testing" to "UNRESTRICTED DESTRUCTIVE penetration testing"
- Injects a `<safety_override>` block that lifts rate limiting, politeness constraints, and adds aggressive recon directives
- Zero false positive enforcement is tightened further

Set to `false` for passive/non-destructive engagements or when working in shared/production environments.

```json
// Production-safe assessment
"allow_destructive_testing": false

// Full offensive engagement (authorized)
"allow_destructive_testing": true
```

---

## 8. Browser Settings

### `browser_page_load_delay`
**Type:** float | **Default:** `1.0` seconds

How long to wait after a page navigation before performing browser actions. Increase for slow targets or heavily JavaScript-rendered pages.

```json
// Fast, well-performing targets
"browser_page_load_delay": 0.5

// Slow targets or heavy SPAs (React, Vue, Angular)
"browser_page_load_delay": 3.0
```

---

## 9. Search Settings

### `searxng_url`
**Type:** string | **Default:** `"http://localhost:8080"`

The URL of your SearXNG instance. If set, the `web_search` tool uses SearXNG for full Google dork operator support.

```json
// Local SearXNG (default)
"searxng_url": "http://localhost:8080"

// Empty = DuckDuckGo fallback (limited operators, rate-limited)
"searxng_url": ""
```

Ollama Shadow auto-manages the SearXNG Docker container lifecycle (start on use, stop on exit). To start manually:

```bash
docker run -d --name searxng -p 8080:8080 searxng/searxng
```

---

### `searxng_engines`
**Type:** string | **Default:** `"google,bing,duckduckgo,brave,google_news,github,stackoverflow"`

Comma-separated list of engines to query via SearXNG.

```json
// Full engine set (slower but broader)
"searxng_engines": "google,bing,duckduckgo,brave,startpage,github,stackoverflow,reddit,google_scholar,google_news"

// Fast subset for quick lookups
"searxng_engines": "google,bing,duckduckgo"
```

---

## 10. Session Settings

### `vuln_similarity_threshold`
**Type:** float | **Default:** `0.7`

Jaccard similarity threshold for vulnerability deduplication. When a new vulnerability finding has similarity ≥ this value compared to an existing entry, it is merged rather than added as a duplicate.

| Value | Behavior |
|-------|----------|
| `0.9` | Only near-identical findings are merged — more duplicates allowed |
| `0.7` | **Default** — reasonable deduplication for most cases |
| `0.5` | Aggressive deduplication — similar findings merged even if endpoint differs |
| `0.3` | Very aggressive — not recommended |

---

### `agent_plan_revision_interval`
**Type:** int | **Default:** `30`

How many iterations between full plan revision checkpoints. At each checkpoint, the agent reviews all findings and updates its exploitation plan.

---

## 11. Environment Variable Overrides

Any config key can be overridden without editing the file using environment variables. Format: `OLLAMA_SHADOW_<KEY_UPPERCASE>`.

```bash
# Override model
OLLAMA_SHADOW_OLLAMA_MODEL=qwen3:32b ollama-shadow start

# Override temperature
OLLAMA_SHADOW_OLLAMA_TEMPERATURE=0.2 ollama-shadow start

# Disable destructive testing
OLLAMA_SHADOW_ALLOW_DESTRUCTIVE_TESTING=false ollama-shadow start

# Use a different Ollama endpoint
OLLAMA_SHADOW_OLLAMA_URL=http://10.0.0.5:11434 ollama-shadow start
```

**Type conversion rules:**
- `bool`: accepts `true`, `1`, `yes` → True | `false`, `0`, `no` → False
- `int` / `float`: standard numeric conversion
- `string`: used as-is

Environment variables take precedence over the config file. They are applied at startup and do not persist.

---

## 12. Configuration Presets

### Preset: Minimum viable (16 GB VRAM, qwen3:30b-a3b MoE)

```json
{
    "ollama_model": "qwen3:30b-a3b",
    "ollama_num_ctx": 32768,
    "ollama_num_ctx_small": 16384,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 8192,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "command_timeout": 600.0,
    "agent_max_tool_iterations": 300,
    "searxng_url": "http://localhost:8080"
}
```

> Note: `qwen3:30b-a3b` is a Mixture-of-Experts model — it has fewer *active* parameters than the full 30B, making it faster and more VRAM-efficient while retaining comparable reasoning quality.

### Preset: Recommended (20 GB VRAM, qwen3:32b)

```json
{
    "ollama_model": "qwen3:32b",
    "ollama_num_ctx": 65536,
    "ollama_num_ctx_small": 32768,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 16384,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "command_timeout": 900.0,
    "agent_max_tool_iterations": 500,
    "searxng_url": "http://localhost:8080"
}
```

### Preset: High-end (48+ GB VRAM, qwen3.5:122b)

```json
{
    "ollama_model": "qwen3.5:122b",
    "ollama_num_ctx": 65536,
    "ollama_num_ctx_small": 32768,
    "ollama_temperature": 0.15,
    "ollama_num_predict": 16384,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "command_timeout": 900.0,
    "agent_max_tool_iterations": 500,
    "searxng_url": "http://localhost:8080"
}
```

### Preset: Remote Ollama (GPU server)

```json
{
    "ollama_url": "http://192.168.1.100:11434",
    "ollama_model": "qwen3.5:122b",
    "ollama_timeout": 3600.0,
    "ollama_num_ctx": 65536,
    "ollama_temperature": 0.15,
    "ollama_enable_thinking": true,
    "ollama_supports_thinking": true,
    "ollama_supports_native_tools": true,
    "ollama_keep_alive": "60m",
    "agent_max_tool_iterations": 1000,
    "searxng_url": "http://localhost:8080"
}
```

### Preset: Passive / non-destructive assessment

```json
{
    "ollama_temperature": 0.15,
    "allow_destructive_testing": false,
    "deep_recon_autostart": false,
    "command_timeout": 300.0,
    "agent_max_tool_iterations": 100
}
```
