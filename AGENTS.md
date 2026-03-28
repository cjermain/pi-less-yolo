# AGENTS.md

## Project purpose

`pi-less-yolo` is a mise shim that runs `pi-coding-agent` inside a sandboxed
Chainguard Docker container, restricting the agent to the mounted working
directory only. There is no build system or test suite beyond shell scripts, a
Dockerfile, and a CI smoke test.

## Key files

| Path | Role |
|---|---|
| `Dockerfile` | Single-stage Chainguard node image; installs curl, git, tmux, mise, uv, Python, and pi |
| `tasks/pi/_common` | Sourced (not executed) by all pi tasks; defines `DOCKER_FLAGS` (security options, volume mounts, env-var forwarding) |
| `tasks/pi/_default` | `mise run pi` — launches the agent in the container |
| `tasks/pi/build` | `mise run pi:build` — builds the Docker image |
| `tasks/pi/shell` | `mise run pi:shell` — opens bash in the container with identical mounts |
| `tasks/pi/upgrade` | `mise run pi:upgrade` — bumps `ARG PI_VERSION` in `Dockerfile` and rebuilds |
| `tasks/pi/health` | `mise run pi:health` — checks mise version, Docker, image, task files, `~/.pi/agent`, and tmux |
| `.mise/tasks/ci` | `mise run ci` — lint → build → smoke test (local equivalent of CI) |
| `.mise/tasks/install` | Writes `~/.config/mise/conf.d/pi-less-yolo.toml` to register tasks globally |
| `.mise/tasks/uninstall` | Removes the global config file |
| `.mise/tasks/update` | `git pull` in the repo root; no reinstall needed |
| `.mise/tasks/lint/_default` | Runs `lint:shell` then `lint:docker` |
| `.mise/tasks/lint/shell` | shellcheck on all executable scripts under `tasks/` and `.mise/tasks/` |
| `.mise/tasks/lint/docker` | hadolint on `Dockerfile` |
| `.mise.toml` | Pins tool versions (shellcheck, hadolint) for local development |
| `.hadolint.yaml` | Suppresses four intentional hadolint rules with justification comments (DL3002, DL3018, DL3059, DL4006) |
| `.github/workflows/ci.yml` | CI: lint job + build job (image build, `--version` smoke test, `python3 --version`) |
| `renovate.json` | Renovate config (see below) |
| `.github/dependabot.yml` | Dependabot config (see below) |

## Development workflow

The Docker socket is intentionally absent from the container — mounting it
would grant full host filesystem access via a trivial container escape, defeating
the entire security model.

From within a `mise run pi` session, run `mise run lint` to validate scripts
and the Dockerfile. For anything that requires Docker (`mise run ci`,
`mise run pi:build`, smoke tests), exit the container and run on the host.
Commit the changes and let CI handle build validation if a host shell isn't
available.

On a fresh clone, two setup steps are required before any tasks will work:

```bash
mise trust          # trust .mise.toml so mise will install tools from it
mise run install    # register tasks/pi/ globally via ~/.config/mise/conf.d/pi-less-yolo.toml
```

`mise run ci` calls `mise run pi:build`, which is defined in `tasks/pi/` and only
resolvable after `install` has been run. Without it, mise will error with
`no task pi:build found`.

Day-to-day commands:

```bash
mise run lint    # shellcheck + hadolint
mise run ci      # lint + docker build + smoke test
```

`MISE_PROJECT_ROOT` and `MISE_TASK_DIR` are available inside all task scripts.

## Conventions

- **All task scripts must pass `shellcheck -x` and `hadolint`** — CI enforces both.
- `tasks/pi/_common` is *sourced*, not executed — no shebang, not executable.
- `#MISE raw=true` and `#MISE dir="{{cwd}}"` on `_default` and `shell` are intentional: they preserve raw terminal I/O and ensure the container's working directory matches the caller's. Do not remove them.
- Docker security flags (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user $(id -u):$(id -g)`) are non-negotiable. Do not weaken them.
- `--network=host` appears only in `pi:build` on Linux (DNS workaround). It must not appear in runtime `DOCKER_FLAGS`.
- When adding a new provider API key: add it to the `PI_ENV_VARS` array in `tasks/pi/_common` **and** the auth table in `README.md`.
- Use `perl -pi -e` for in-place file edits (cross-platform; avoids `sed -i` / `sed -i ''` incompatibility between Linux and macOS).

## Automated dependency updates

### Renovate

`renovate.json` uses `config:recommended` with two managers disabled (Docker image digests and GitHub Actions — those are handled by Dependabot) and four custom `regexManagers` that track versions embedded directly in `Dockerfile` and `README.md`:

| Dependency | Location | Datasource |
|---|---|---|
| `mise` | `MISE_VERSION=` in `Dockerfile` | GitHub Releases (`jdx/mise`) |
| `uv` | `UV_VERSION=` in `Dockerfile` | GitHub Releases (`astral-sh/uv`) |
| Python | `uv python install <ver>` in `Dockerfile` | GitHub Tags (`python/cpython`) |
| `@mariozechner/pi-coding-agent` | `ARG PI_VERSION=` in `Dockerfile` and badge in `README.md` | npm |

Both `Dockerfile` and `README.md` must be updated together when pi's version changes (Renovate handles both via the same `matchStrings` list).

### Dependabot

`.github/dependabot.yml` runs weekly on a 7-day cooldown for:

- **Docker** — the `FROM` image digest in `Dockerfile`
- **GitHub Actions** — action versions in `.github/workflows/`

## GitHub Actions

`.github/workflows/ci.yml` triggers on push and pull requests to `main`. It has two independent jobs:

| Job | Steps |
|---|---|
| `lint` | Checkout → mise-action → `mise run lint` |
| `build` | Checkout → Docker Buildx → build image (GHA cache) → smoke test `--version` → smoke test `python3 --version` |

The build job uses `docker/build-push-action` with `push: false` and `load: true` so the built image is available for the smoke tests without being pushed to a registry.
