ARG PI_VERSION=0.61.0

FROM cgr.dev/chainguard/node:latest-dev@sha256:e927b4c376506296d78e45a9702d41aeeb86a4c694b8af5afe6a1cb1f34f064c

# Install git, tmux, curl, and ca-certificates via Wolfi's apk.
# Node.js (LTS) and npm are pre-installed in the base image.
USER root
RUN apk add --no-cache \
        curl \
        ca-certificates \
        git \
        tmux

# Install pi globally
RUN npm install -g @mariozechner/pi-coding-agent@${PI_VERSION}

# Install mise and uv
RUN curl -fsSL https://mise.run \
        | MISE_VERSION=2026.3.9 MISE_INSTALL_PATH=/usr/local/bin/mise sh \
    && curl -fsSL https://astral.sh/uv/install.sh \
        | UV_VERSION=0.10.12 UV_INSTALL_DIR=/usr/local/bin sh

# Create a world-writable home directory so any runtime UID (supplied via
# `docker run --user $(id -u):$(id -g)`) can write here even without a
# corresponding /etc/passwd entry. The sticky bit (1777, same as /tmp)
# prevents other UIDs from deleting each other's files.
RUN mkdir -p /home/piuser && chmod 1777 /home/piuser

# Create the workspace mountpoint
RUN mkdir -p /workspace

# Point HOME at the shared dir above. pi's own config path is overridden at
# runtime via PI_CODING_AGENT_DIR, so this HOME is only a fallback for any
# other tooling that needs a writable home (e.g. git credential helpers).
ENV HOME=/home/piuser

WORKDIR /workspace

ENTRYPOINT ["pi"]
