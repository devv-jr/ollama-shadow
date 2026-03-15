"""Ollama Shadow CLI entry point."""

from __future__ import annotations

import argparse
import sys
import logging

from ollama_shadow.proxy.config import get_container_runtime


def main() -> None:

    import importlib.metadata

    try:
        version = importlib.metadata.version("ollama-shadow")
    except importlib.metadata.PackageNotFoundError:
        version = "0.1.5"

    parser = argparse.ArgumentParser(
        prog="ollama-shadow",
        description="Ollama Shadow — AI-powered security reconnaissance",
    )
    # Global arguments
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {version}")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to custom configuration file (default: ~/.ollama-shadow/config.json)")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all saved sessions and exit")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # proxy subcommand
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start proxy server only")
    proxy_parser.add_argument("--host", default=None, help="Host to bind to")
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to")
    proxy_parser.add_argument(
        "--config",
        default=None,
        help="Path to custom configuration file")

    # tui subcommand
    tui_parser = subparsers.add_parser(
        "start", help="Start TUI client (also starts proxy)")
    tui_parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Don't auto-start proxy")
    tui_parser.add_argument(
        "--proxy-url",
        default="http://127.0.0.1:3000",
        help="Proxy URL")
    tui_parser.add_argument(
        "--config",
        default=None,
        help="Path to custom configuration file")
    tui_parser.add_argument(
        "--session", default=None,
        metavar="SESSION_ID",
        help="Resume a previous session by ID (e.g. ollama-shadow start --session 1740842400_a3b4c5d6)",
    )

    # status subcommand
    status_parser = subparsers.add_parser(
        "status", help="Check status of services")
    status_parser.add_argument(
        "--config",
        default=None,
        help="Path to custom configuration file")

    # clean subcommand
    clean_parser = subparsers.add_parser(
        "clean",
        help="Clean Docker build cache, orphan containers, and unused volumes"
    )
    clean_parser.add_argument(
        "--all", "-a", action="store_true",
        help="Full clean: also remove the ollama-shadow-sandbox image (requires full rebuild next time)"
    )
    clean_parser.add_argument(
        "--keep-storage", default="3gb",
        help="Minimum build cache to keep for fast rebuilds (default: 3gb). Use 0 to remove all."
    )

    args = parser.parse_args()

    # Initialize config globally with the provided path (if any)
    # This ensures subsequent calls to get_config() return the correct instance
    from ollama_shadow.proxy.config import get_config
    get_config(args.config)

    if getattr(args, "list", False):
        _run_list_sessions()
        sys.exit(0)

    if args.command == "proxy":
        _run_proxy(args)
    elif args.command == "start":
        _run_tui(args)
    elif args.command == "status":
        _run_status(args)
    elif args.command == "clean":
        _run_clean(args)
    else:
        parser.print_help()
        sys.exit(1)


def _run_proxy(args) -> None:
    """Start the proxy server."""
    import atexit
    atexit.register(_unload_model_safely)
    import os
    import ollama_shadow.proxy.config as _cfg_module

    # Set env vars BEFORE resetting the singleton so they are picked up
    if args.host:
        os.environ["OLLAMA_SHADOW_PROXY_HOST"] = args.host
    if args.port:
        os.environ["OLLAMA_SHADOW_PROXY_PORT"] = str(args.port)

    # Reset singleton so the env-var overrides take effect
    if args.host or args.port:
        _cfg_module._config = None
        _cfg_module.get_config(getattr(args, "config", None))

    from ollama_shadow.proxy.server import run_server
    run_server()


def _run_tui(args) -> None:
    """Start TUI (optionally with embedded proxy)."""
    import atexit
    atexit.register(_unload_model_safely)
    import threading
    import os

    # If a session ID was requested, pass it via env var so the proxy picks it
    # up
    if getattr(args, "session", None):
        os.environ["OLLAMA_SHADOW_SESSION_ID"] = args.session
        print(f"[Ollama Shadow] Resuming session: {args.session}", flush=True)

    # Ensure config is loaded
    from ollama_shadow.proxy.config import get_config
    cfg = get_config()

    # ----- DOCKER AUTO-BUILD CHECK -----
    import asyncio
    from ollama_shadow.proxy.docker import DockerEngine

    print("\n[Ollama Shadow] Checking Docker Sandbox environment...", flush=True)
    engine = DockerEngine()
    build_success = asyncio.run(engine.ensure_image())
    if not build_success:
        print(
            "\n\033[31m[!] Critical: Failed to find or build the Docker image ('ollama-shadow-sandbox').\033[0m")
        print("Please check Docker is installed and running, or build manually:")
        print(f"  docker build -t ollama-shadow-sandbox {engine.DOCKERFILE_DIR}")
        sys.exit(1)
    # -----------------------------------

    # ----- SEARXNG AUTO-START CHECK -----
    from ollama_shadow.proxy.searxng import SearXNGManager

    _should_manage_searxng = (
        not cfg.searxng_url
        or "localhost" in cfg.searxng_url
        or "127.0.0.1" in cfg.searxng_url
    )
    if _should_manage_searxng:
        print("\n[Ollama Shadow] Checking SearXNG search engine...", flush=True)
        _searxng_mgr = SearXNGManager()
        _searxng_url = asyncio.run(_searxng_mgr.ensure_running())
        if _searxng_url:
            # Auto-write searxng_url into user config if it was empty
            if not cfg.searxng_url:
                _set_config_value("searxng_url", _searxng_url)
            print(f"[Ollama Shadow] SearXNG ready at {_searxng_url}", flush=True)
        else:
            print(
                "[Ollama Shadow] SearXNG failed to start — falling back to DuckDuckGo.",
                flush=True,
            )
    # ------------------------------------

    if not args.no_proxy:
        # Start proxy in background thread
        _proxy_error: list[str] = []

        def start_proxy():
            import logging
            import traceback
            # Suppress proxy logs (they go to stderr and mess with TUI)
            # We use CRITICAL to be absolutely sure nothing leaks
            logging.getLogger("ollama_shadow").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
            logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
            logging.getLogger("httpx").setLevel(logging.CRITICAL)
            logging.getLogger("httpcore").setLevel(logging.CRITICAL)

            try:
                from ollama_shadow.proxy.server import run_server
                run_server()
            except Exception as e:
                _proxy_error.append(str(e))
                with open("ollama_shadow_proxy_crash.log", "w") as f:
                    traceback.print_exc(file=f)

        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        # Wait for proxy to be ready (MCP connection takes ~5s)
        import time
        import urllib.request

        # Use config or args for URL
        proxy_url = args.proxy_url.rstrip("/")
        # If user didn't override proxy_url, use config default
        if args.proxy_url == "http://127.0.0.1:3000":
            proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"

        print(f"Starting Ollama Shadow proxy at {proxy_url}... ", end="", flush=True)

        for attempt in range(40):  # up to 20 seconds
            # Check if proxy thread crashed immediately
            if _proxy_error:
                print(f"\n[!] Proxy failed to start: {_proxy_error[0]}")
                print("    Check ollama_shadow_proxy_crash.log for details.")
                sys.exit(1)

            try:
                req = urllib.request.urlopen(  # nosec B310 - localhost proxy only
                    f"{proxy_url}/api/status", timeout=2)
                import json
                data = json.loads(req.read())
                # Proxy is responding — services may still be initializing
                docker_ok = data.get("docker", {}).get("connected", False)
                ollama_ok = data.get("ollama", {}).get("connected", False)
                if docker_ok and ollama_ok:
                    print("ready!")
                else:
                    print("proxy running.")
                break
            except Exception:
                print(".", end="", flush=True)
                time.sleep(0.5)
        else:
            if _proxy_error:
                print(f"\n[!] Proxy crashed: {_proxy_error[0]}")
                print("    Check ollama_shadow_proxy_crash.log for details.")
                sys.exit(1)
            print(" (proxy did not respond — check for port conflicts)")

    from ollama_shadow.tui.app import OllamaShadowApp

    # If using custom config, the proxy_url arg might need to follow config unless overridden
    # But for TUI client, args.proxy_url is the target.
    # Logic: If config changed port, TUI should know.
    # We used args.proxy_url default "http://127.0.0.1:3000".
    # If config says port 4000, we should probably use that unless user
    # explicitly said --proxy-url ...

    final_proxy_url = args.proxy_url
    if final_proxy_url == "http://127.0.0.1:3000" and not args.no_proxy:
        # Use config values if default was kept
        final_proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"

    # logs globally before starting anything
    logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)
    logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL)
    logging.getLogger("multipart").setLevel(logging.CRITICAL)

    app = OllamaShadowApp(proxy_url=final_proxy_url)
    try:
        app.run()
    except Exception as e:
        # If TUI crashes, we want to see why, but maybe to a file
        with open("ollama_shadow_crash.log", "w") as f:
            import traceback
            traceback.print_exc(file=f)
        print(
            f"Ollama Shadow TUI crashed! Check ollama_shadow_crash.log for details.\nError: {e}")
        sys.exit(1)


def _run_status(args) -> None:
    """Check status of all services."""
    import asyncio
    import httpx
    import re as _re

    async def check():
        from ollama_shadow.proxy.config import get_config
        import importlib.metadata
        cfg = get_config()

        try:
            version = importlib.metadata.version("ollama-shadow")
        except importlib.metadata.PackageNotFoundError:
            version = "0.1.5"

        # Colors
        G = "\033[32m"   # green
        R = "\033[31m"   # red
        Y = "\033[33m"   # yellow
        C = "\033[36m"   # cyan
        B = "\033[1m"    # bold
        D = "\033[2m"    # dim
        X = "\033[0m"    # reset
        ON  = f"{G}● online{X}"
        OFF = f"{R}● offline{X}"

        W = 74  # inner box width (chars between the two ║)
        _ANSI = _re.compile(r'\033\[[0-9;]*m')

        def _vlen(s: str) -> int:
            """Visible length after stripping ANSI escape codes."""
            return len(_ANSI.sub('', s))

        def _row(content: str = "") -> str:
            """One padded box row: ║ content<spaces> ║"""
            pad = max(0, W - _vlen(content))
            return f"  {C}║{X}{content}{' ' * pad}{C}║{X}"

        print()
        print(f"  {C}╔{'═' * W}╗{X}")
        print(_row(f"  {B}▄▖▄▖▄▖{X}"))
        print(_row(f"  {B}▌▌▐ ▙▘█▌▛▘▛▌▛▌{X}"))
        print(_row(f"  {B}▛▌▟▖▌▌▙▖▙▖▙▌▌▌{X}"))
        print(_row(f"  {D}v{version} — AI-Powered Security Reconnaissance{X}"))
        print(f"  {C}╠{'═' * W}╣{X}")

        # ── Ollama ──
        ollama_status = OFF
        model_names: list[str] = []
        active_model = cfg.ollama_model
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{cfg.ollama_url}/api/tags")
                models = resp.json().get("models", [])
                model_names = [m["name"] for m in models]
                ollama_status = ON
        except Exception:  # nosec B110 - status check, best-effort
            pass

        print(_row())
        print(_row(f"  {B}Ollama{X}        {ollama_status}"))
        print(_row(f"  {D}Endpoint:{X}     {cfg.ollama_url}"))
        print(_row(f"  {D}Active Model:{X} {Y}{active_model}{X}"))
        if model_names:
            # Build model list — 3 per line, aligned under "Available:" label
            label = f"  {D}Available:{X}    "
            indent = " " * _vlen(label)
            line_content = label
            for i, name in enumerate(model_names):
                cell = f"{G}{name}{X}" if name == active_model else f"{D}{name}{X}"
                if i > 0 and i % 3 == 0:
                    print(_row(line_content))
                    line_content = indent
                elif i % 3 > 0:
                    line_content += "  "
                line_content += cell
            print(_row(line_content))

        # ── Docker ──
        print(_row())
        docker_status = OFF
        docker_detail = ""
        try:
            import shutil
            import subprocess as sp  # nosec B404
            _docker = shutil.which(get_container_runtime()) or get_container_runtime()
            result = sp.run(  # nosec B603
                [_docker, "ps", "--filter", "name=ollama-shadow-sandbox-active",
                 "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout.strip():
                docker_status = f"{G}● running{X}"
                docker_detail = result.stdout.strip()
            else:
                docker_status = f"{Y}● standby{X}"
                docker_detail = "Container starts on first tool call"
        except Exception:
            docker_status = f"{R}● not found{X}"
            docker_detail = "Docker is not installed or not in PATH"

        print(_row(f"  {B}Docker{X}        {docker_status}"))
        if docker_detail:
            print(_row(f"  {D}Detail:{X}       {docker_detail}"))

        # ── SearXNG ──
        print(_row())
        searxng_status = OFF
        searxng_detail = ""
        try:
            import shutil
            import subprocess as sp  # nosec B404
            _docker = shutil.which(get_container_runtime()) or get_container_runtime()
            result = sp.run(  # nosec B603
                [_docker, "ps", "--filter", "name=ollama-shadow-searxng",
                 "--filter", "status=running", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout.strip():
                searxng_configured = bool(cfg.searxng_url)
                searxng_status = (f"{G}● running{X}" if searxng_configured
                                  else f"{Y}● running (unconfigured){X}")
                searxng_detail = cfg.searxng_url or "http://localhost:8080 (auto-managed)"
            else:
                searxng_status = f"{Y}● stopped{X}"
                searxng_detail = "Starts automatically with 'ollama-shadow start'"
        except Exception:
            searxng_status = f"{Y}● unknown{X}"
            searxng_detail = "Docker not available"

        print(_row(f"  {B}SearXNG{X}       {searxng_status}"))
        if searxng_detail:
            print(_row(f"  {D}Endpoint:{X}     {searxng_detail}"))

        # ── Proxy ──
        print(_row())
        proxy_url = f"http://{cfg.proxy_host}:{cfg.proxy_port}"
        proxy_status = OFF
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{proxy_url}/api/status")
                if resp.status_code == 200:
                    proxy_status = ON
        except Exception:  # nosec B110 - status check, best-effort
            pass

        print(_row(f"  {B}Proxy{X}         {proxy_status}"))
        print(_row(f"  {D}Endpoint:{X}     {proxy_url}"))

        print(_row())
        print(f"  {C}╚{'═' * W}╝{X}")
        print()

    asyncio.run(check())


def _set_config_value(key: str, value: str) -> None:
    """Write a single key into ~/.ollama-shadow/config.json without touching other values."""
    import json
    from pathlib import Path

    config_file = Path.home() / ".ollama-shadow" / "config.json"
    try:
        current: dict = {}
        if config_file.exists():
            with open(config_file) as f:
                current = json.load(f)
        current[key] = value
        with open(config_file, "w") as f:
            json.dump(current, f, indent=4)
        # Reload the singleton so the rest of the session sees the new value
        from ollama_shadow.proxy.config import reload_config
        reload_config()
    except Exception as e:
        print(f"[!] Could not update config {key}: {e}")


def _unload_model_safely():
    """Attempt to unload model safely on exit using curl (most robust)."""
    try:
        from ollama_shadow.proxy.config import get_config
        import shutil
        import subprocess  # nosec B404
        import json

        # Try to get loaded config, or load default
        try:
            cfg = get_config()
        except BaseException:
            # Fallback if config completely fails
            return

        _docker = shutil.which(get_container_runtime()) or get_container_runtime()
        url = cfg.ollama_url.rstrip("/")
        model = cfg.ollama_model

        print("\n[Ollama Shadow] Cleaning up Docker Sandbox...", end="", flush=True)
        subprocess.run(  # nosec B603
            [_docker, "rm", "-f", "ollama-shadow-sandbox-active"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5)
        print("Done.")

        # Remove SearXNG container on exit (image is kept, so next start is
        # fast)
        try:
            from ollama_shadow.proxy.config import get_config as _gc
            _cfg = _gc()
            if not _cfg.searxng_url or "localhost" in _cfg.searxng_url or "127.0.0.1" in _cfg.searxng_url:
                from ollama_shadow.proxy.searxng import CONTAINER_NAME as _SX_NAME
                subprocess.run(  # nosec B603
                    [_docker, "rm", "-f", _SX_NAME],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                )
        except Exception:  # nosec B110
            pass

        print(
            f"[Ollama Shadow] Unloading model '{model}' (releasing VRAM)... ",
            end="",
            flush=True)

        # Construct curl command
        # curl -X POST http://localhost:11434/api/generate -d '{"model": "...",
        # "keep_alive": 0}'
        cmd = [
            "curl", "-s", "-X", "POST", f"{url}/api/generate",
            "-d", json.dumps({"model": model, "keep_alive": 0})
        ]

        # Run with timeout — cmd is hardcoded with no user input
        subprocess.run(  # nosec B603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2)
        print("Done.")

    except Exception:
        try:
            import urllib.request
            import json

            print(
                "\n[Ollama Shadow] Cleaning up Docker Sandbox...",
                end="",
                flush=True)
            import shutil as _shutil
            import subprocess  # nosec B404
            _docker2 = _shutil.which(get_container_runtime()) or get_container_runtime()
            subprocess.run(  # nosec B603
                [_docker2, "rm", "-f", "ollama-shadow-sandbox-active"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5)
            print("Done.")

            print(
                "[Ollama Shadow] Unloading model (releasing VRAM)... ",
                end="",
                flush=True)

            # Fetch config again strictly for the urllib try block
            from ollama_shadow.proxy.config import get_config
            cfg = get_config()
            url = cfg.ollama_url.rstrip("/")
            model = cfg.ollama_model

            data = json.dumps(
                {"model": model, "keep_alive": 0}).encode("utf-8")
            req = urllib.request.Request(
                f"{url}/api/generate", data=data, method="POST")
            urllib.request.urlopen(req, timeout=2)  # nosec B310 - localhost only
            print("Done (via urllib).")
        except Exception:
            print("Failed.")


def _run_list_sessions() -> None:
    """List all saved sessions and exit."""
    from ollama_shadow.proxy.agent.session import list_sessions

    C = "\033[36m"   # cyan
    B = "\033[1m"    # bold
    D = "\033[2m"    # dim
    G = "\033[32m"   # green
    Y = "\033[33m"   # yellow
    X = "\033[0m"    # reset

    sessions = list_sessions()

    print()
    if not sessions:
        print(f"  {D}No saved sessions found.{X}")
        print(f"  Start a new session: {C}ollama-shadow start{X}")
        print()
        return

    # Header
    print(f"  {B}{'SESSION ID':<28} {'TARGET':<24} {'SCANS':>5}  {'SUBS':>4}  {'VULNS':>5}  CREATED{X}")
    print(f"  {'─' * 28} {'─' * 24} {'─' * 5}  {'─' * 4}  {'─' * 5}  {'─' * 10}")

    for s in sessions:
        sid = s["session_id"]
        target = s["target"] or f"{D}(no target){X}"
        scans = s["scan_count"]
        subs = s.get("subdomains", 0)
        vulns = s.get("vulnerabilities", 0)
        created = s.get("created_at", "")[:10]  # just the date part

        # Colour-code vulns
        vuln_str = f"{Y}{vulns:>5}{X}" if vulns > 0 else f"{D}{vulns:>5}{X}"
        print(
            f"  {G}{sid:<28}{X} {target:<24} {scans:>5}  {subs:>4}  {vuln_str}  {D}{created}{X}"
        )

    print()
    print(f"  Resume: {C}ollama-shadow start --session <id>{X}")
    print()


def _run_clean(args) -> None:
    """Clean Docker build cache, orphan containers, and unused volumes."""
    import subprocess  # nosec B404
    import shutil

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    CHECK = "✅"
    WARN = "⚠️ "
    BROOM = "🧹"

    if not shutil.which(get_container_runtime()):
        print(f"{RED}[!] No container runtime (podman/docker) found.{RESET}")
        sys.exit(1)

    _rt = get_container_runtime()

    def run(cmd: list[str],
            capture: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(  # nosec B603
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )

    def get_docker_df() -> dict:
        """Return dict with Docker disk usage totals."""
        r = run([_rt, "system", "df", "--format",
                "{{json .}}"], capture=True)
        # docker system df --format json outputs multiple lines (one per type)
        totals = {
            "images": "?",
            "containers": "?",
            "volumes": "?",
            "cache": "?"}
        if r.returncode == 0:
            import json
            for line in r.stdout.decode(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    t = obj.get("Type", "")
                    reclaimable = obj.get("Reclaimable", "?")
                    if "Image" in t:
                        totals["images"] = reclaimable
                    elif "Container" in t:
                        totals["containers"] = reclaimable
                    elif "Volume" in t:
                        totals["volumes"] = reclaimable
                    elif "Cache" in t or "Build" in t:
                        totals["cache"] = reclaimable
                except Exception:  # nosec B110 - best-effort JSON parsing
                    pass
        return totals

    print(f"\n{BOLD}{BROOM} Ollama Shadow Docker Cleanup{RESET}")
    print("─" * 48)

    # ── Show before state ──
    print(f"\n{CYAN}[Before Cleanup]{RESET}")
    run([_rt, "system", "df"])

    freed_items: list[str] = []

    # ── 1. Remove any leftover ollama-shadow containers (sandbox + searxng) ──
    print(
        f"\n{YELLOW}[1/4] Removing orphan ollama-shadow containers...{RESET}",
        end=" ",
        flush=True)
    containers = run(
        [_rt, "ps", "-a", "-q", "--filter", "name=ollama-shadow"],
        capture=True
    )
    ids = containers.stdout.decode().strip().split() if containers.returncode == 0 else []
    if ids:
        for cid in ids:
            run([_rt, "rm", "-f", cid])
        print(f"{CHECK} Removed {len(ids)} container(s)")
        freed_items.append(f"{len(ids)} orphan container(s)")
    else:
        print("None found.")

    # ── 2. Prune build cache ──
    keep = getattr(args, "keep_storage", "3gb")
    if keep == "0":
        cache_cmd = [_rt, "builder", "prune", "-af"]
        label = "all build cache"
    else:
        cache_cmd = [
            _rt,
            "builder",
            "prune",
            "-f",
            f"--keep-storage={keep}"]
        label = f"build cache (keeping {keep} for fast rebuilds)"

    print(f"{YELLOW}[2/4] Pruning {label}...{RESET}", end=" ", flush=True)
    result = run(cache_cmd, capture=True)
    if result.returncode == 0:
        output = result.stdout.decode(errors="replace")
        # Try to parse the freed space line from docker output
        freed_line = next((line for line in output.splitlines()
                          if "freed" in line.lower() or "Total" in line), "")
        print(f"{CHECK} {freed_line.strip() or 'Done'}")
        freed_items.append("build cache layers")
    else:
        print(f"{WARN} Failed (non-critical)")

    # ── 3. Prune unused volumes ──
    print(
        f"{YELLOW}[3/4] Pruning unused Docker volumes...{RESET}",
        end=" ",
        flush=True)
    vol_result = run([_rt, "volume", "prune", "-f"], capture=True)
    if vol_result.returncode == 0:
        vol_out = vol_result.stdout.decode(errors="replace")
        freed_vol = next((line for line in vol_out.splitlines()
                         if "freed" in line.lower() or "Total" in line), "")
        print(f"{CHECK} {freed_vol.strip() or 'Done'}")
        freed_items.append("unused volumes")
    else:
        print(f"{WARN} Failed (non-critical)")

    # ── 4. Optionally remove sandbox image ──
    full_clean = getattr(args, "all", False)
    if full_clean:
        print(
            f"{YELLOW}[4/4] Removing ollama-shadow-sandbox image (--all flag)...{RESET}",
            end=" ",
            flush=True)
        img_result = run(
            [_rt, "rmi", "-f", "ollama-shadow-sandbox"], capture=True)
        if img_result.returncode == 0:
            print(
                f"{CHECK} Removed. Next `ollama-shadow start` will rebuild (~10-20 min).")
            freed_items.append("ollama-shadow-sandbox image (12.5GB)")
        else:
            print("Not found or already removed.")
    else:
        print(
            f"{YELLOW}[4/4] Sandbox image kept{RESET} (use --all to remove it too)")

    # ── Show after state ──
    print(f"\n{CYAN}[After Cleanup]{RESET}")
    run([_rt, "system", "df"])

    print(f"\n{GREEN}{BOLD}{CHECK} Cleanup complete!{RESET}")
    if freed_items:
        for item in freed_items:
            print(f"   • Freed: {item}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
