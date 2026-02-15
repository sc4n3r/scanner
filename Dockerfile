FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git python3 python3-pip nodejs npm ca-certificates xz-utils make \
    && rm -rf /var/lib/apt/lists/*

# Git identity (needed for forge install / submodule operations)
RUN git config --global user.email "scanner@sc4n3r.app" \
    && git config --global user.name "sc4n3r"

# Foundry (forge, cast, solc management)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

# Aderyn (Cyfrin static analyzer)
RUN curl --proto '=https' --tlsv1.2 -LsSf \
    https://github.com/cyfrin/aderyn/releases/latest/download/aderyn-installer.sh | bash

# Python tools (core)
RUN pip3 install --no-cache-dir \
    solc-select \
    slither-analyzer \
    pyyaml \
    requests

# Mythril — optional deep analysis (may fail on ARM/aarch64)
RUN pip3 install --no-cache-dir mythril || \
    echo "WARNING: mythril install failed (expected on ARM). Deep analysis will be unavailable."

# Solhint (Solidity linter)
RUN npm install -g solhint --silent

# Default solc
RUN solc-select install 0.8.20 && solc-select use 0.8.20

# Application
COPY audit/ /app/audit/
COPY entrypoint.py /app/entrypoint.py

# Gemini API key (passed at runtime or build time)
ARG GEMINI_API_KEY=""
RUN if [ -n "$GEMINI_API_KEY" ]; then \
    echo "GEMINI_API_KEY=$GEMINI_API_KEY" >> /etc/environment; \
    fi
ENV GEMINI_API_KEY=$GEMINI_API_KEY

WORKDIR /target

ENTRYPOINT ["python3", "/app/entrypoint.py"]
