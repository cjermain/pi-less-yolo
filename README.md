# pi-less-yolo

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![pi version](https://img.shields.io/badge/pi--coding--agent-0.74.1-blueviolet)](https://github.com/earendil-works/pi/tree/main/packages/coding-agent)
[![Base Image](https://img.shields.io/badge/base%20image-chainguard%2Fnode-F4835E?logo=docker)](https://images.chainguard.dev/directory/image/node/overview)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/cjermain/pi-less-yolo/blob/main/.github/dependabot.yml)
[![mise](https://mise-versions.jdx.dev/badge.svg)](https://mise.jdx.dev)
[![CI](https://img.shields.io/github/actions/workflow/status/cjermain/pi-less-yolo/ci.yml?style=flat&label=CI)](https://github.com/cjermain/pi-less-yolo/actions/workflows/ci.yml)

> Run [pi-coding-agent](https://github.com/earendil-works/pi/tree/main/packages/coding-agent) (a multi-provider AI coding agent supporting Claude, GPT, Gemini, and [many more](https://github.com/earendil-works/pi/tree/main/packages/coding-agent#providers--models)) inside an isolated Docker container — limiting the blast radius of agent-driven changes to your mounted working directory.

![pi-less-yolo demo: filesystem isolation proof and AI-assisted bug fix](docs/demo.gif)

A [mise](https://mise.jdx.dev) shim that wraps the **pi** AI coding agent in a [Chainguard](https://chainguard.dev)-based container with your current directory and `~/.pi/agent` volume-mounted — and nothing else.

Pi defaults to running with full access to your filesystem. This repo constrains it so the agent cannot touch files outside your project, cannot escalate privileges, and runs as your own user.

> **This is "less YOLO", not "no YOLO".** Container escapes exist. The mounted directories are fully writable. This is a meaningful reduction in risk, not a security guarantee.

## Why use this?

AI coding agents are powerful — and dangerous. A hallucinating model, a misunderstood instruction, or a runaway loop can delete, overwrite, or exfiltrate files anywhere on your machine. `pi-less-yolo` gives you a practical safety net:

- **Filesystem isolation** — the agent can only read and write your current project directory.
- **No privilege escalation** — all Linux capabilities are dropped; `no-new-privileges` is set.
- **Reproducible environment** — a pinned, minimal Chainguard Node image with only the tools pi needs.
- **Zero friction** — one `mise run pi` command from any project; no manual Docker incantations.

If you use [Claude Code](https://docs.anthropic.com/en/docs/claude-code), Aider, Cursor, or any other LLM-based coding assistant and want sandboxed execution, this pattern applies to you.

## Prerequisites

- [mise](https://mise.jdx.dev/installing-mise.html) >= 2024.12.0
- [Docker](https://docs.docker.com/get-docker/) (Desktop on macOS, Engine on Linux) or [Podman](https://podman.io/getting-started/installation) (via `PI_CONTAINER_RUNTIME=podman`, the `podman-docker` package, or a symlink)
- git

## Install

```bash
git clone https://github.com/cjermain/pi-less-yolo.git
cd pi-less-yolo
mise run install
```

`install` writes a single file — `~/.config/mise/conf.d/pi-less-yolo.toml` — that points mise at the `tasks/` directory in the cloned repo. The five pi tasks become available globally from any directory. The repo must stay at the cloned path; if you move it, re-run `mise run install`.

Then build the Docker image (one-time, ~2 minutes):

```bash
mise run pi:build
```

## Usage

Run pi from any project directory:

```bash
cd ~/my-project
mise run pi
```

Your current directory is mounted at its real path inside the container (e.g. `/home/you/my-project`). Pi uses this path for session tracking, so each project gets its own session history. Pi's config, sessions, and credentials are mounted from `~/.pi/agent`. Files written by the agent are owned by your user on the host.

### Non-interactive use

Pi's `-p` flag runs a single prompt and exits. All arguments after `--` are passed through to pi:

```bash
mise run pi -- -p "summarize this repo"
```

Piped stdin is also supported:

```bash
cat README.md | mise run pi -- -p "summarize this"
git diff | mise run pi -- -p "write a commit message for this diff"
```

This works with `pi:readonly` too:

```bash
cat src/auth.ts | mise run pi:readonly -- -p "review for security issues"
```

### Alias (optional)

To type `pi` instead of `mise run pi`, add to your shell profile:

```bash
alias pi='mise run pi'
```

> **Task name collision warning:** If any project you work in defines its own `pi` mise task, the project-local task will take precedence over the global one inside that directory. Run `mise tasks --global` to confirm which `pi` task is active.

## Available mise tasks

| Task | Description |
|---|---|
| `mise run pi` | Run the pi AI coding agent in the sandboxed container |
| `mise run pi:pi-acp` | Run pi-acp to provide Agent Client Protocol (ACP) stdio connection for IDE's to connect (same mounts as pi)|
| `mise run pi:readonly` | Run pi with the project directory mounted read-only and file-modification tools disabled |
| `mise run pi:build` | Build or rebuild the Docker container image |
| `mise run pi:shell` | Open a bash shell in the container (same mounts as `pi`) |
| `mise run pi:upgrade` | Upgrade pi to the latest npm release and rebuild |
| `mise run pi:health` | Check the setup for common problems |

## Agent Client Protocol (ACP) Connections

The `mise run pi:pi-acp` task command can be utilzed for connecting IDE's over [ACP](https://agentclientprotocol.com/overview/introduction) to the Pi coding agent in the sandboxed container.

The task will install [pi-acp](https://github.com/svkozak/pi-acp) to the `/pi-agent/npm-global` shared directory, if not already installed.

Most IDE's will expect to run the `pi-acp` command, so add this to your shell profile:

```bash
alias pi-acp='mise run pi:pi-acp'
```

To update the package run the task `mise run pi:shell` and once inside the shell container run `npm install -g pi-acp` at the prompt.


## Staying current

### Update the shim (new features in this repo)

```bash
cd /path/to/pi-less-yolo
mise run update
```

`git pull` is all that's needed. Because mise includes the `tasks/` directory directly, changes go live immediately with no reinstall.

### Upgrade pi to the latest release

```bash
mise run pi:upgrade
```

Fetches the latest `@earendil-works/pi-coding-agent` version from npm, updates the `npm install -g` line in `Dockerfile`, and rebuilds the image.

## Health check

```bash
mise run pi:health
```

Checks mise version, Docker availability, image existence, task files, npm (for upgrade), `~/.pi/agent`, and tmux passthrough support.

## Uninstall

```bash
cd /path/to/pi-less-yolo
mise run uninstall
```

Removes `~/.config/mise/conf.d/pi-less-yolo.toml`. The Docker image and `~/.pi/agent` are left untouched.

To remove everything:

```bash
mise run uninstall
docker rmi pi-less-yolo:latest
rm -rf ~/.pi/agent
rm -rf /path/to/pi-less-yolo
```

## Authentication

Pi supports two ways to authenticate with a provider:

**API key via environment variable** (recommended for scripted or non-interactive use):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
mise run pi
```

The following environment variables are forwarded from your host into the container:

| Provider | Environment Variable |
|---|---|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` |
| Google Gemini | `GEMINI_API_KEY` |
| Mistral | `MISTRAL_API_KEY` |
| Groq | `GROQ_API_KEY` |
| Cerebras | `CEREBRAS_API_KEY` |
| xAI | `XAI_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |
| Vercel AI Gateway | `AI_GATEWAY_API_KEY` |
| ZAI | `ZAI_API_KEY` |
| OpenCode | `OPENCODE_API_KEY` |
| Kimi | `KIMI_API_KEY` |
| MiniMax | `MINIMAX_API_KEY` |
| MiniMax (China) | `MINIMAX_CN_API_KEY` |

Pi config variables (`PI_SKIP_VERSION_CHECK`, `PI_CACHE_RETENTION`, `PI_PACKAGE_DIR`) and editor variables (`VISUAL`, `EDITOR`) are also forwarded. No other host environment variables are passed into the container.

**Auth file** (`~/.pi/agent/auth.json`): credentials stored here take priority over environment variables. Use `/login` inside pi to set this up interactively. See [pi's provider docs](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/providers.md) for details.

## Security model

The container is launched with:

- `--user $(id -u):$(id -g)` — files created inside the container are owned by your host user
- `--cap-drop=ALL` — all Linux capabilities dropped
- `--security-opt=no-new-privileges` — prevents privilege escalation via setuid binaries
- `--ipc=none` — isolated IPC namespace; no shared memory with other containers
- `--volume $(pwd):$(pwd)` — your current directory is mounted at its real host path; the container's working directory is set to match
- `--volume ~/.pi/agent:/pi-agent` — pi config, credentials, and sessions

Mounting the directory at its real path (rather than a fixed `/workspace`) means pi's session tracking reflects the actual project path, so each project gets distinct session history.

The agent cannot reach other directories on your host. It can make arbitrary network requests and execute any command available inside the container image.

### Read-only mode

`mise run pi:readonly` mounts the project directory read-only and restricts pi to the `read`, `grep`, `find`, and `ls` tools. The agent can answer questions about the codebase but cannot write files or run shell commands — enforced at the kernel level via the `:ro` volume mount.

Use it for untrusted or sensitive codebases.

### Pi packages

Pi packages installed inside the container (`pi install npm:...`, `pi install git:...`)
are written to `~/.pi/agent/npm-global/lib/node_modules/` and `~/.pi/agent/git/` and loaded as extensions on
every subsequent run. A prompt-injected install persists to the host and survives the
session.

> **Accepted risk.** Audit installed packages with `pi list` and review
> `~/.pi/agent/git/` and `~/.pi/agent/npm/` periodically.

### Git identity

If `~/.gitconfig` exists on the host it is mounted read-only at startup, so the agent can make `git commit` with your correct author identity. Opt out by setting `PI_NO_GITCONFIG=1`.

> **Note:** credential helpers referenced in `~/.gitconfig` (e.g. `osxkeychain`, `libsecret`) are not available inside the container. They fail gracefully — git falls back to prompting for credentials.

### Container context prompt

By default pi is told it is running inside a Docker container as a non-root user, and that the Docker socket, sudo, and system package installation are unavailable. This prevents the agent from confidently suggesting commands that will fail. Opt out by setting `PI_NO_CONTAINER_PROMPT=1`.

### SSH agent forwarding

SSH is **disabled by default**. Set `PI_SSH_AGENT=1` to forward the host SSH agent socket into the container, enabling SSH-based git remotes (`git clone git@github.com:...`) without private keys ever entering the container.

```bash
PI_SSH_AGENT=1 mise run pi
```

Or export it in your shell profile to make it permanent.

> **Security note:** a compromised container can authenticate as you to any SSH server your agent has loaded. Review loaded keys with `ssh-add -l` before enabling. On macOS, Docker Desktop exposes the host SSH agent via a fixed path inside the VM. The socket is created root-owned with restricted permissions; the root group (GID 0) is added as a supplementary group so the non-root container user can access it — no additional setup is needed. On Linux, ensure `ssh-agent` is running and `SSH_AUTH_SOCK` is exported in your shell environment.

### Local models (Ollama, LM Studio, vLLM)

Local model servers are **disabled by default**. Set `PI_LOCAL_MODELS=1` to share
the host network namespace, making `localhost` inside the container identical to
`localhost` on the host. Model URLs that work when running pi natively work
identically inside the container with no changes to `models.json` or to the model
server's binding address.

Create `~/.pi/agent/models.json` using the same URL you would use on the host:

```json
{
  "providers": {
    "ollama": {
      "baseUrl": "http://localhost:11434/v1",
      "api": "openai-completions",
      "apiKey": "ollama",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false
      },
      "models": [
        { "id": "llama3.1:8b" }
      ]
    }
  }
}
```

Then start pi with the flag and select the model with `/model`:

```bash
PI_LOCAL_MODELS=1 mise run pi
```

Or export it in your shell profile to make it permanent.

> **Security note:** `--network=host` makes all host ports reachable from inside
> the container, not just the model server port. `--cap-drop=ALL` and
> `--no-new-privileges` remain in force.

> **macOS:** `--network=host` uses the Docker Desktop Linux VM's network namespace,
> not the Mac's. Localhost services on macOS are not reachable this way. Use
> `host.docker.internal` as the `baseUrl` in `models.json` instead — Docker
> Desktop routes that hostname to the Mac host correctly.

### Resource limits

By default no memory, CPU, or process-count limits are applied. Set any of these
variables to cap resource usage:

| Variable | Docker flag | Example |
|---|---|---|
| `PI_MEMORY` | `--memory` | `PI_MEMORY=4g` |
| `PI_CPUS` | `--cpus` | `PI_CPUS=2` |
| `PI_PIDS_LIMIT` | `--pids-limit` | `PI_PIDS_LIMIT=512` |

```bash
PI_MEMORY=4g PI_PIDS_LIMIT=512 mise run pi
```

Or export in your shell profile to make them permanent.

### Linux: `--network=host` at build time

On Linux, Docker's default bridge network cannot reach `127.0.0.53` (systemd-resolved). `pi:build` uses `--network=host` during the build only to work around this. This does not affect runtime.

To fix this permanently instead:

1. Find your upstream nameserver: `resolvectl status | grep "DNS Server"`
2. Add to `/etc/docker/daemon.json`: `{ "dns": ["<upstream-ip>"] }`
3. Restart dockerd
4. Remove the `--network=host` line from `tasks/pi/build`

## Podman support

`pi-less-yolo` works with [Podman](https://podman.io) as a drop-in Docker replacement.
Podman is automatically detected when the `docker` command in PATH resolves to the
podman binary — either via a compatibility wrapper or a symlink.

The runtime adds `--userns=keep-id` when podman is detected, which properly maps user
namespaces and avoids TTY ownership errors.

Set `PI_CONTAINER_RUNTIME=podman` to use podman explicitly without relying on detection:

```bash
PI_CONTAINER_RUNTIME=podman mise run pi
```

If you don't have a `docker` compatibility shim, the `podman-docker` package is the
recommended way to provide one:

```bash
# Fedora/RHEL:
sudo dnf install podman-docker

# Ubuntu/Debian:
sudo apt install podman-docker
```

Or create a symlink manually (no package required):

```bash
sudo ln -s "$(which podman)" /usr/local/bin/docker
```

> **Note:** Shell aliases (`alias docker=podman`) are only expanded in interactive
> shells. Mise tasks run as non-interactive bash subprocesses and cannot see aliases
> defined in your shell profile — see the
> [Bash manual on Aliases](https://www.gnu.org/software/bash/manual/bash.html#Aliases).
> Use `PI_CONTAINER_RUNTIME=podman`, the `podman-docker` package, or a symlink instead.

All tasks (`pi`, `pi:readonly`, `pi:build`, `pi:shell`) work identically with podman.

## Customising the container

To modify the container — adding tools, changing the base image, pinning different versions — edit `Dockerfile` and rebuild:

```bash
# Edit Dockerfile...
mise run pi:build
```

The `npm install -g` line near the bottom of `Dockerfile` pins the pi version. `mise run pi:upgrade` updates it automatically; you can also edit the version string by hand.

## Related projects

- [pi-coding-agent](https://github.com/earendil-works/pi) — the upstream AI coding agent this repo wraps
- [mise](https://mise.jdx.dev) — the polyglot dev-tool manager used for task running
- [Chainguard Images](https://chainguard.dev) — minimal, hardened container base images used here
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — Anthropic's official sandboxed coding agent CLI, a similar concept

---

**Keywords:** docker sandbox AI coding agent, sandboxed LLM agent, pi-coding-agent docker, isolated Claude CLI, mise AI task runner, Chainguard AI container, prevent AI agent filesystem access, secure coding agent container, ai agent docker isolation
