# pi-less-yolo

A [mise](https://mise.jdx.dev) shim that runs [pi-coding-agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) inside a Docker container, limiting the blast radius of agent-driven changes to your mounted working directory.

Pi defaults to running with full access to your filesystem. This repo constrains it to a Chainguard-based container with your current directory and `~/.pi/agent` volume-mounted — and nothing else.

> **This is "less YOLO", not "no YOLO".** Container escapes exist. The mounted directories are fully writable. This is a meaningful reduction in risk, not a security guarantee.

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

Your current directory is mounted at `/workspace` inside the container. Pi's config, sessions, and credentials are mounted from `~/.pi/agent`. Files written by the agent are owned by your user on the host.

### Alias (optional)

To type `pi` instead of `mise run pi`, add to your shell profile:

```bash
alias pi='mise run pi'
```

> **Task name collision warning:** If any project you work in defines its own `pi` mise task, the project-local task will take precedence over the global one inside that directory. Run `mise tasks --global` to confirm which `pi` task is active.

## Tasks

| Task | Description |
|---|---|
| `mise run pi` | Run pi in the container |
| `mise run pi:build` | Build or rebuild the Docker image |
| `mise run pi:shell` | Open a bash shell in the container (same mounts as `pi`) |
| `mise run pi:upgrade` | Upgrade pi to the latest npm release and rebuild |
| `mise run pi:health` | Check the setup for problems |

## Staying current

### Update the shim (new features in this repo)

```bash
cd /path/to/pi-less-yolo
mise run update
```

`git pull` is all that's needed. Because mise includes the `tasks/` directory directly, changes go live immediately with no reinstall.

### Upgrade pi (new pi releases)

```bash
mise run pi:upgrade
```

Fetches the latest version from npm, updates `ARG PI_VERSION` in `Dockerfile`, and rebuilds the image.

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
- `--volume $(pwd):/workspace` — only your current directory is accessible
- `--volume ~/.pi/agent:/pi-agent` — pi config, credentials, and sessions

The agent cannot reach other directories on your host. It can make arbitrary network requests and execute any command available inside the container image.

### Linux: `--network=host` at build time

On Linux, Docker's default bridge network cannot reach `127.0.0.53` (systemd-resolved). `pi:build` uses `--network=host` during the build only to work around this. This does not affect runtime.

To fix this permanently instead:

1. Find your upstream nameserver: `resolvectl status | grep "DNS Server"`
2. Add to `/etc/docker/daemon.json`: `{ "dns": ["<upstream-ip>"] }`
3. Restart dockerd
4. Remove the `--network=host` line from `tasks/pi/build`

## Customisation

To modify the container — adding tools, changing the base image, pinning different versions — edit `Dockerfile` and rebuild:

```bash
# Edit Dockerfile...
mise run pi:build
```

The `ARG PI_VERSION` line at the top of `Dockerfile` controls the pi version. `mise run pi:upgrade` updates it automatically; you can also edit it by hand.
