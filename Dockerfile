FROM cgr.dev/chainguard/node:latest-dev@sha256:4ab907c3dccb83ebfbf2270543da99e0241ad2439d03d9ac0f69fe18497eb64a

# openssh-client: ssh binary for git-over-SSH (PI_SSH_AGENT=1) and ssh-add.
USER root
RUN apk add --no-cache \
        curl \
        ca-certificates \
        git \
        openssh-client \
        tmux

# Install mise and uv
RUN curl -fsSL https://mise.run \
        | MISE_VERSION=2026.3.18 MISE_INSTALL_PATH=/usr/local/bin/mise sh \
    && curl -fsSL https://astral.sh/uv/install.sh \
        | UV_VERSION=0.11.2 UV_INSTALL_DIR=/usr/local/bin sh

ENV UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python

# Install Python via uv and expose it on PATH
RUN uv python install 3.14.3 \
    && ln -s "$(uv python find 3.14.3)" /usr/local/bin/python3

# Install pi globally
RUN npm install -g "@mariozechner/pi-coding-agent@0.64.0"

# /home/piuser: world-writable (1777) so any runtime UID can write here.
# /home/piuser/.ssh: root-owned 755; SSH accepts it and the runtime user can
#   read mounts inside it (700 would block a non-matching UID).
# /etc/passwd: world-writable so the entrypoint can add the runtime UID.
#   SSH calls getpwuid(3) and hard-fails without a passwd entry. Safe here
#   because --cap-drop=ALL and --no-new-privileges block privilege escalation.
RUN mkdir -p /home/piuser /home/piuser/.ssh \
    && chmod 1777 /home/piuser \
    && chmod 755 /home/piuser/.ssh \
    && chmod a+w /etc/passwd \
    && touch /home/piuser/.ssh/known_hosts \
    && chmod 666 /home/piuser/.ssh/known_hosts

ENV HOME=/home/piuser

# Register the runtime UID in /etc/passwd before starting pi.
# SSH calls getpwuid(3) and hard-fails without an entry; nss_wrapper is
# unavailable in Wolfi so we append directly.
RUN <<'EOF'
cat > /usr/local/bin/entrypoint.sh << 'ENTRYPOINT'
#!/bin/sh
set -e

if ! grep -q "^[^:]*:[^:]*:$(id -u):" /etc/passwd; then
    printf 'piuser:x:%d:%d:piuser:%s:/bin/sh\n' \
        "$(id -u)" "$(id -g)" "${HOME}" >> /etc/passwd
fi

# Pass through to a shell when invoked via `pi:shell`; otherwise run pi.
case "${1:-}" in
    bash|sh) exec "$@" ;;
    *) exec pi "$@" ;;
esac
ENTRYPOINT
chmod +x /usr/local/bin/entrypoint.sh
EOF

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
