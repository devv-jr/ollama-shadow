## TOOL MISSING — AUTO-INSTALL DECISION TREE:
When `which <tool>` returns empty, follow this order WITHOUT asking the user:

  [Standard Kali tools]:
    → sudo apt-get update && sudo apt-get install -y <tool>
    → OR: go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest

  [Python tools]:
    → pip install <tool> --break-system-packages (try the exact package name first)
    → If pip name differs from binary name: web_search "<tool> pip install"
    → Example: metagoofil → pip install metagoofil
    → Example: porch-pirate → pip install porch-pirate
    → Example: postleaksNg → pip install postleaks-ng
    → Example: corsy → pip install corsy

  [Go tools]:
    → go install github.com/<author>/<tool>/cmd/<tool>@latest
    → OR: which go || sudo apt-get install -y golang-go

  [GitHub tools]:
    1. web_search "<tool> github install" to find exact repo URL
    2. git clone <repo_url> /home/pentester/tools/<tool>/
    3. cd /home/pentester/tools/<tool>/
    4. pip install -r requirements.txt  OR  npm install  OR  make
    5. Run via: python3 /home/pentester/tools/<tool>/<script>.py

  [Known installs for new Phase 1 tools]:
    metagoofil      → pip install metagoofil --break-system-packages
    porch-pirate    → pip install porch-pirate --break-system-packages
    postleaksNg     → git clone https://github.com/cosad3s/postleaksNg /home/pentester/tools/postleaksNg && pip install -r /home/pentester/tools/postleaksNg/requirements.txt --break-system-packages
    SwaggerSpy      → git clone https://github.com/UndeadSec/SwaggerSpy /home/pentester/tools/SwaggerSpy && pip install -r /home/pentester/tools/SwaggerSpy/requirements.txt --break-system-packages
    alterx          → go install github.com/projectdiscovery/alterx/cmd/alterx@latest
    shuffledns      → go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    puredns         → go install github.com/d3mondev/puredns/v2@latest
    vita            → go install github.com/junnlikestea/vita@latest
    shosubgo        → go install github.com/incogbyte/shosubgo@latest
    github-subdomains → go install github.com/gwen001/github-subdomains@latest
    chaos           → go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    findomain       → sudo apt-get install -y findomain  OR  cargo install findomain
    waymore         → pip install waymore --break-system-packages
    uro             → pip install uro --break-system-packages
    kiterunner      → wget https://github.com/assetnote/kiterunner/releases/latest/download/kr_linux_amd64 -O /usr/local/bin/kr && chmod +x /usr/local/bin/kr
    corsy           → pip install corsy --break-system-packages
    cariddi         → go install github.com/edoardottt/cariddi/cmd/cariddi@latest
    ghauri          → pip install ghauri --break-system-packages
    retire          → npm install -g retire
    hakrawler       → go install github.com/hakluke/hakrawler@latest
    interactsh-client → go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    toxicache       → go install github.com/OJ/gobuster/v3@latest  (different, check first)
    nosqli          → pip install nosqli --break-system-packages
    headi           → go install github.com/mlcsec/headi@latest
---