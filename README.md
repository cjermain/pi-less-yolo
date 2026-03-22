# pi-less-yolo

> Run [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) (a multi-provider AI coding agent supporting Claude, GPT, Gemini, and [many more](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent#providers--models)) inside an isolated Docker container — limiting the blast radius of agent-driven changes to your mounted working directory.

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
- [Docker](https://docs.docker.com/get-docker/) (Desktop on macOS, Engine on Linux)
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
| `mise run pi:build` | Build or rebuild the Docker container image |
| `mise run pi:shell` | Open a bash shell in the container (same mounts as `pi`) |
| `mise run pi:upgrade` | Upgrade pi to the latest npm release and rebuild |
| `mise run pi:health` | Check the setup for common problems |

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

Fetches the latest `@mariozechner/pi-coding-agent` version from npm, updates `ARG PI_VERSION` in `Dockerfile`, and rebuilds the image.

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

## Security model

The container is launched with:

- `--user $(id -u):$(id -g)` — files created inside the container are owned by your host user
- `--cap-drop=ALL` — all Linux capabilities dropped
- `--security-opt=no-new-privileges` — prevents privilege escalation via setuid binaries
- `--volume $(pwd):$(pwd)` — your current directory is mounted at its real host path; the container's working directory is set to match
- `--volume ~/.pi/agent:/pi-agent` — pi config, credentials, and sessions

Mounting the directory at its real path (rather than a fixed `/workspace`) means pi's session tracking reflects the actual project path, so each project gets distinct session history.

The agent cannot reach other directories on your host. It can make arbitrary network requests and execute any command available inside the container image.

### Linux: `--network=host` at build time

On Linux, Docker's default bridge network cannot reach `127.0.0.53` (systemd-resolved). `pi:build` uses `--network=host` during the build only to work around this. This does not affect runtime.

To fix this permanently instead:

1. Find your upstream nameserver: `resolvectl status | grep "DNS Server"`
2. Add to `/etc/docker/daemon.json`: `{ "dns": ["<upstream-ip>"] }`
3. Restart dockerd
4. Remove the `--network=host` line from `tasks/pi/build`

## Customising the container

To modify the container — adding tools, changing the base image, pinning different versions — edit `Dockerfile` and rebuild:

```bash
# Edit Dockerfile...
mise run pi:build
```

The `ARG PI_VERSION` line at the top of `Dockerfile` controls the pi version. `mise run pi:upgrade` updates it automatically; you can also edit it by hand.

## Related projects

- [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) — the upstream AI coding agent this repo wraps
- [mise](https://mise.jdx.dev) — the polyglot dev-tool manager used for task running
- [Chainguard Images](https://chainguard.dev) — minimal, hardened container base images used here
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) — Anthropic's official sandboxed coding agent CLI, a similar concept

---

**Keywords:** docker sandbox AI coding agent, sandboxed LLM agent, pi-coding-agent docker, isolated Claude CLI, mise AI task runner, Chainguard AI container, prevent AI agent filesystem access, secure coding agent container, ai agent docker isolation
