FROM cgr.dev/chainguard/node:latest-dev@sha256:d201cee80fc4bd2881571d9d7c25c3551a32281d655409c80d9c600214afa5cf

# openssh-client: ssh binary for git-over-SSH (PI_SSH_AGENT=1) and ssh-add.
USER root
RUN apk add --no-cache \
        curl \
        ca-certificates \
        git \
        openssh-client \
        tmux

# Install mise (GPG-verified via mise-release.asc).
RUN --mount=type=bind,source=mise-release.asc,target=/tmp/mise-release.asc <<'EOF'
set -e
apk add --no-cache gpg gpg-agent
gpg --import /tmp/mise-release.asc
curl -fsSL https://mise.jdx.dev/install.sh.sig -o /tmp/mise-install.sh.sig
gpg --decrypt /tmp/mise-install.sh.sig > /tmp/mise-install.sh
MISE_VERSION=2026.4.9 MISE_INSTALL_PATH=/usr/local/bin/mise sh /tmp/mise-install.sh
rm /tmp/mise-install.sh.sig /tmp/mise-install.sh
apk del gpg gpg-agent
EOF

# ARG (not ENV): available during build, not baked in. At runtime mise defaults
# to ~/.local/share/mise, which the container user can write to.
ARG MISE_DATA_DIR=/usr/local/share/mise

# Install uv via mise and expose uv and uvx on PATH.
RUN <<'EOF'
set -e
mise install uv@0.11.6
ln -s "$(mise exec uv@0.11.6 -- which uv)" /usr/local/bin/uv
ln -s "$(mise exec uv@0.11.6 -- which uvx)" /usr/local/bin/uvx
EOF

ENV UV_PYTHON_INSTALL_DIR=/usr/local/share/uv/python

# Install Python via uv and expose it on PATH
RUN uv python install 3.14.4 \
    && ln -s "$(uv python find 3.14.4)" /usr/local/bin/python3

# Install pi globally
RUN npm install -g "@mariozechner/pi-coding-agent@0.66.1"

# Prepend extension binaries (host-mounted via /pi-agent). Security: binaries
# here can shadow any command; no privilege escalation (--cap-drop=ALL,
# --no-new-privileges), but review ~/.pi/agent/npm-global/bin/ after installs.
ENV PATH="/pi-agent/npm-global/bin:${PATH}"

# /home/piuser: world-writable (1777) so any runtime UID can write here.
# /home/piuser/.ssh: root-owned 755; SSH accepts it and the runtime user can
#   read mounts inside it (700 would block a non-matching UID).
# /etc/passwd: world-writable so the entrypoint can add the runtime UID.
#   SSH calls getpwuid(3) and hard-fails without a passwd entry. Safe here
#   because --cap-drop=ALL and --no-new-privileges block privilege escalation.
# .npmrc sets prefix=/pi-agent/npm-global so extensions persist across restarts.
# Written as a literal file because ENV HOME is not yet set to /home/piuser.
RUN mkdir -p /home/piuser /home/piuser/.ssh \
    && chmod 1777 /home/piuser \
    && chmod 755 /home/piuser/.ssh \
    && chmod a+w /etc/passwd \
    && touch /home/piuser/.ssh/known_hosts \
    && chmod 666 /home/piuser/.ssh/known_hosts \
    && echo "prefix=/pi-agent/npm-global" > /home/piuser/.npmrc

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
