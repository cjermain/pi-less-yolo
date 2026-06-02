import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { stripJsonComments, loadFile, loadConfig } from "./config.ts";
import { matchesPath, matchesBash } from "./match.ts";
import register from "./security.ts";
import type { SecurityConfig } from "./config.ts";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

describe("suite smoke", () => {
  it("runs", () => assert.equal(1, 1));
});

describe("stripJsonComments", () => {
  it("removes line comments", () => {
    assert.equal(stripJsonComments(`{\n  "a": 1 // trailing\n}`), `{\n  "a": 1 \n}`);
  });
  it("removes block comments", () => {
    assert.equal(stripJsonComments(`{ /* hi */ "a": 1 }`), `{  "a": 1 }`);
  });
  it("keeps // inside strings", () => {
    assert.equal(stripJsonComments(`{"url": "http://x"}`), `{"url": "http://x"}`);
  });
  it("keeps /* inside strings", () => {
    assert.equal(stripJsonComments(`{"s": "/* not a comment */"}`), `{"s": "/* not a comment */"}`);
  });
});

describe("loadFile", () => {
  const dir = mkdtempSync(join(tmpdir(), "sec-"));
  it("returns EMPTY-shaped config when file missing", () => {
    const r = loadFile(join(dir, "nope.json"));
    assert.deepEqual(r, {
      enabled: undefined,
      filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
      bash: { deny: [] },
    });
  });
  it("parses a valid .json file", () => {
    const p = join(dir, "g.json");
    writeFileSync(p, JSON.stringify({
      enabled: false,
      filesystem: {
        denyRead: ["a"],
        denyWrite: ["b"],
        mountMask: [".env"],
        isolateDirs: ["node_modules"],
      },
      bash: { deny: ["sudo"] },
    }));
    assert.deepEqual(loadFile(p), {
      enabled: false,
      filesystem: {
        denyRead: ["a"],
        denyWrite: ["b"],
        mountMask: [".env"],
        isolateDirs: ["node_modules"],
      },
      bash: { deny: ["sudo"] },
    });
  });
  it("absent mountMask and isolateDirs default to empty arrays", () => {
    const p = join(dir, "no-host-fields.json");
    writeFileSync(p, JSON.stringify({
      filesystem: { denyRead: ["a"], denyWrite: ["b"] },
      bash: { deny: [] },
    }));
    const r = loadFile(p);
    assert.deepEqual(r.filesystem.mountMask, []);
    assert.deepEqual(r.filesystem.isolateDirs, []);
  });
  it("drops non-string entries from mountMask and isolateDirs", () => {
    const p = join(dir, "mixed-types.json");
    writeFileSync(p, JSON.stringify({
      filesystem: {
        denyRead: [],
        denyWrite: [],
        mountMask: [".env", 42, null, ".env.local"],
        isolateDirs: [true, "node_modules", {}, ".venv"],
      },
      bash: { deny: [] },
    }));
    const r = loadFile(p);
    assert.deepEqual(r.filesystem.mountMask, [".env", ".env.local"]);
    assert.deepEqual(r.filesystem.isolateDirs, ["node_modules", ".venv"]);
  });
  it("parses .jsonc with comments", () => {
    const p = join(dir, "g.jsonc");
    writeFileSync(p, `{
      // a comment
      "bash": { "deny": ["rm -rf"] /* block */ }
    }`);
    const r = loadFile(p);
    assert.deepEqual(r.bash.deny, ["rm -rf"]);
  });
  it("returns empty config and warns on malformed JSON", (t) => {
    const p = join(dir, "bad.json");
    writeFileSync(p, `{ not json`);
    const warn = t.mock.method(console, "warn");
    const r = loadFile(p);
    assert.deepEqual(r.filesystem.denyRead, []);
    assert.equal(warn.mock.callCount(), 1);
  });
});

describe("loadConfig", () => {
  it("missing file → default enabled true, empty arrays", () => {
    const dir = mkdtempSync(join(tmpdir(), "sec-missing-"));
    const r = loadConfig({ dir });
    assert.equal(r.enabled, true);
    assert.deepEqual(r.filesystem.denyRead, []);
    assert.deepEqual(r.filesystem.denyWrite, []);
    assert.deepEqual(r.bash.deny, []);
  });
  it("reads security.jsonc with comments", () => {
    const dir = mkdtempSync(join(tmpdir(), "sec-jsonc-"));
    writeFileSync(join(dir, "security.jsonc"), `{
      // rules
      "enabled": true,
      "filesystem": {
        "denyRead": ["~/.ssh/**"],
        "denyWrite": ["*.pem"],
        "mountMask": [".env", ".env.local"],
        "isolateDirs": ["node_modules", ".venv"]
      },
      "bash": { "deny": ["sudo"] }
    }`);
    const r = loadConfig({ dir });
    assert.equal(r.enabled, true);
    assert.deepEqual(r.filesystem.denyRead, ["~/.ssh/**"]);
    assert.deepEqual(r.filesystem.denyWrite, ["*.pem"]);
    assert.deepEqual(r.filesystem.mountMask, [".env", ".env.local"]);
    assert.deepEqual(r.filesystem.isolateDirs, ["node_modules", ".venv"]);
    assert.deepEqual(r.bash.deny, ["sudo"]);
  });
  it("falls back to security.json when .jsonc is absent", () => {
    const dir = mkdtempSync(join(tmpdir(), "sec-json-"));
    writeFileSync(join(dir, "security.json"), JSON.stringify({
      enabled: false,
      filesystem: { denyRead: [".env"], denyWrite: [] },
      bash: { deny: [] },
    }));
    const r = loadConfig({ dir });
    assert.equal(r.enabled, false);
    assert.deepEqual(r.filesystem.denyRead, [".env"]);
  });
  it("prefers security.jsonc over security.json when both exist", () => {
    const dir = mkdtempSync(join(tmpdir(), "sec-both-"));
    writeFileSync(join(dir, "security.jsonc"), JSON.stringify({ bash: { deny: ["from-jsonc"] } }));
    writeFileSync(join(dir, "security.json"), JSON.stringify({ bash: { deny: ["from-json"] } }));
    assert.deepEqual(loadConfig({ dir }).bash.deny, ["from-jsonc"]);
  });
});

describe("matchesPath — basename patterns", () => {
  it(".env matches deeply nested .env", () => {
    const r = matchesPath("/a/b/c/.env", [".env"]);
    assert.equal(r.matched, true);
    assert.equal(r.rule, ".env");
  });
  it(".env does NOT match .envfile", () => {
    assert.equal(matchesPath("/a/.envfile", [".env"]).matched, false);
  });
  it(".env.* matches .env.local but not .env", () => {
    assert.equal(matchesPath("/a/.env.local", [".env.*"]).matched, true);
    assert.equal(matchesPath("/a/.env", [".env.*"]).matched, false);
  });
  it("*.pyc matches any .pyc", () => {
    assert.equal(matchesPath("/x/y/z.pyc", ["*.pyc"]).matched, true);
  });
  it("no pattern matches → no match", () => {
    assert.equal(matchesPath("/x/y", [".env", "*.pem"]).matched, false);
  });
  it("? matches a single non-slash char", () => {
    assert.equal(matchesPath("/a/b.c", ["?.c"]).matched, true);
    assert.equal(matchesPath("/a/bb.c", ["?.c"]).matched, false);
  });
});

describe("matchesPath — anchored + tilde", () => {
  const cwd = process.cwd();
  it(".claude/worktrees/** matches under project root only", () => {
    assert.equal(
      matchesPath(join(cwd, ".claude/worktrees/x/y.txt"), [".claude/worktrees/**"]).matched,
      true,
    );
    assert.equal(
      matchesPath("/elsewhere/.claude/worktrees/x", [".claude/worktrees/**"]).matched,
      false,
    );
  });
  it("**/.ipynb_checkpoints matches any depth under cwd", () => {
    assert.equal(
      matchesPath(join(cwd, "a/b/.ipynb_checkpoints"), ["**/.ipynb_checkpoints"]).matched,
      true,
    );
  });
  it("~/.ssh/** matches inside home", () => {
    assert.equal(matchesPath(join(homedir(), ".ssh/id_rsa"), ["~/.ssh/**"]).matched, true);
  });
  it("/abs/path matches absolute target", () => {
    assert.equal(matchesPath("/etc/passwd", ["/etc/passwd"]).matched, true);
  });
  it("trailing-slash directory pattern matches dir + children", () => {
    assert.equal(
      matchesPath(join(cwd, "node_modules/foo/x.js"), ["node_modules/"]).matched,
      true,
    );
  });
});

describe("matchesBash — token prefix", () => {
  it("matches leading-token command", () => {
    const r = matchesBash("rm -rf /foo", ["rm -rf"]);
    assert.equal(r.matched, true);
    assert.equal(r.rule, "rm -rf");
  });
  it("does not match when tokens mid-command", () => {
    assert.equal(matchesBash("cat rm -rf notes", ["rm -rf"]).matched, false);
  });
  it("git push matches git push --force but not git pushd", () => {
    assert.equal(matchesBash("git push --force", ["git push"]).matched, true);
    assert.equal(matchesBash("git pushd /tmp", ["git push"]).matched, false);
  });
  it("single-token rule sudo matches any sudo invocation", () => {
    assert.equal(matchesBash("sudo apt install foo", ["sudo"]).matched, true);
  });
  it("no patterns → no match", () => {
    assert.equal(matchesBash("anything", []).matched, false);
  });
});

describe("matchesBash — operator splitting", () => {
  it("matches after pipe", () => {
    assert.equal(matchesBash("foo | rm -rf /", ["rm -rf"]).matched, true);
  });
  it("matches after &&", () => {
    assert.equal(matchesBash("X=1 && rm -rf .", ["rm -rf"]).matched, true);
  });
  it("matches after ||", () => {
    assert.equal(matchesBash("foo || sudo ls", ["sudo"]).matched, true);
  });
  it("matches after ;", () => {
    assert.equal(matchesBash("echo hi; rm -rf /", ["rm -rf"]).matched, true);
  });
  it("matches inside $(...)", () => {
    assert.equal(matchesBash('echo "$(rm -rf /tmp/x)"', ["rm -rf"]).matched, true);
  });
});

describe("matchesBash — re: regex", () => {
  it("matches via regex where token-prefix cannot", () => {
    const r = matchesBash("echo x > /dev/sda", ["re:>\\s*/dev/sd[a-z]"]);
    assert.equal(r.matched, true);
    assert.equal(r.rule, "re:>\\s*/dev/sd[a-z]");
  });
  it("invalid regex is skipped with a warn, doesn't crash", (t) => {
    const warn = t.mock.method(console, "warn");
    const r = matchesBash("rm -rf /", ["re:[broken", "rm -rf"]);
    assert.equal(r.matched, true);
    assert.equal(r.rule, "rm -rf");
    assert.equal(warn.mock.callCount(), 1);
  });
});

function makePi() {
  const handlers: Record<string, Function> = {};
  const commands: Record<string, { description?: string; handler: Function }> = {};
  return {
    handlers,
    commands,
    on(event: string, handler: Function) {
      handlers[event] = handler;
    },
    registerCommand(name: string, options: { description?: string; handler: Function }) {
      commands[name] = options;
    },
  };
}

function ctx(hasUI = true) {
  const notifications: Array<{ msg: string; level: string }> = [];
  const statuses: Record<string, string | undefined> = {};
  return {
    ctx: {
      hasUI,
      ui: {
        notify: (msg: string, level: string) => notifications.push({ msg, level }),
        setStatus: (key: string, text: string | undefined) => { statuses[key] = text; },
        theme: { fg: (_color: string, text: string) => text },
      },
    },
    notifications,
    statuses,
  };
}

describe("index.ts — session_start", () => {
  it("announces active security with rule counts when enabled + UI", () => {
    const pi = makePi();
    register(pi as any, {
      enabled: true,
      filesystem: { denyRead: ["a"], denyWrite: ["b", "c"], mountMask: [], isolateDirs: [] },
      bash: { deny: ["sudo"] },
    });
    const { ctx: c, notifications: n } = ctx(true);
    pi.handlers.session_start({}, c);
    assert.equal(n.length, 1);
    assert.match(n[0].msg, /security/);
    assert.match(n[0].msg, /1 read/);
    assert.match(n[0].msg, /2 write/);
    assert.match(n[0].msg, /1 bash/);
  });
  it("sets a persistent status bar entry under the 'security' key", () => {
    const pi = makePi();
    register(pi as any, {
      enabled: true,
      filesystem: { denyRead: ["a"], denyWrite: [], bash: [] } as any,
      bash: { deny: [] },
    });
    const { ctx: c, statuses } = ctx(true);
    pi.handlers.session_start({}, c);
    assert.ok(statuses.security);
    assert.match(statuses.security!, /security/);
  });
  it("announces disabled when !enabled", () => {
    const pi = makePi();
    register(pi as any, {
      enabled: false,
      filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
      bash: { deny: [] },
    });
    const { ctx: c, notifications: n, statuses } = ctx(true);
    pi.handlers.session_start({}, c);
    assert.match(n[0].msg, /disabled/);
    assert.match(statuses.security!, /disabled/);
  });
  it("silent when !hasUI", () => {
    const pi = makePi();
    register(pi as any, {
      enabled: true,
      filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
      bash: { deny: [] },
    });
    const { ctx: c, notifications: n, statuses } = ctx(false);
    pi.handlers.session_start({}, c);
    assert.equal(n.length, 0);
    assert.equal(statuses.security, undefined);
  });
});

describe("index.ts — /security command", () => {
  it("registers a 'security' command with a description", () => {
    const pi = makePi();
    register(pi as any, configWith([".env"], [], ["sudo"]));
    assert.ok(pi.commands.security);
    assert.ok(pi.commands.security.description);
  });
  it("prints config path and all rule categories when invoked", async () => {
    const pi = makePi();
    register(pi as any, configWith(["~/.ssh/**"], ["*.pem"], ["rm -rf"]));
    const { ctx: c, notifications: n } = ctx(true);
    await pi.commands.security.handler("", c);
    assert.equal(n.length, 1);
    const msg = n[0].msg;
    assert.match(msg, /config:/);
    assert.match(msg, /security\.jsonc|security\.json/);
    assert.match(msg, /denyRead \(1\)/);
    assert.match(msg, /~\/\.ssh\/\*\*/);
    assert.match(msg, /denyWrite \(1\)/);
    assert.match(msg, /\*\.pem/);
    assert.match(msg, /bash\.deny \(1\)/);
    assert.match(msg, /rm -rf/);
  });
  it("registers the command even when disabled so users can inspect state", async () => {
    const pi = makePi();
    register(pi as any, {
      enabled: false,
      filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
      bash: { deny: [] },
    });
    assert.ok(pi.commands.security);
    const { ctx: c, notifications: n } = ctx(true);
    await pi.commands.security.handler("", c);
    assert.match(n[0].msg, /disabled/);
  });
});

function configWith(denyRead: string[] = [], denyWrite: string[] = [], bashDeny: string[] = []): SecurityConfig {
  return {
    enabled: true,
    filesystem: { denyRead, denyWrite, mountMask: [], isolateDirs: [] },
    bash: { deny: bashDeny },
  };
}

describe("index.ts — tool_call for read-ish tools", () => {
  it("blocks read when path matches denyRead", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "read", input: { path: "/p/.env" } }, c);
    assert.equal(r.block, true);
    assert.match(r.reason, /denyRead/);
    assert.match(r.reason, /\.env/);
  });
  it("does not block read when no match", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "read", input: { path: "/p/src.ts" } }, c);
    assert.equal(r, undefined);
  });
  it("blocks grep, find, ls using same denyRead", async () => {
    const pi = makePi();
    register(pi as any, configWith(["~/.ssh/**"]));
    const { ctx: c } = ctx(false);
    for (const toolName of ["grep", "find", "ls"]) {
      const r = await pi.handlers.tool_call(
        { toolName, input: { path: join(homedir(), ".ssh/id_rsa") } },
        c,
      );
      assert.equal(r.block, true, `${toolName} should block`);
    }
  });
  it("short-circuits when denyRead empty — no matcher call", async () => {
    const pi = makePi();
    register(pi as any, configWith([]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "read", input: { path: "/anything" } }, c);
    assert.equal(r, undefined);
  });
  it("notifies on block when hasUI", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"]));
    const { ctx: c, notifications: n } = ctx(true);
    await pi.handlers.tool_call({ toolName: "read", input: { path: "/p/.env" } }, c);
    const blocks = n.filter((x) => x.msg.includes("🚫"));
    assert.equal(blocks.length, 1);
    assert.match(blocks[0].msg, /Blocked read/);
  });
});

describe("index.ts — tool_call for write-ish tools", () => {
  it("blocks write on denyWrite match", async () => {
    const pi = makePi();
    register(pi as any, configWith([], ["*.pem"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "write", input: { path: "/p/server.pem" } }, c);
    assert.equal(r.block, true);
    assert.match(r.reason, /denyWrite/);
  });
  it("blocks edit on denyWrite match", async () => {
    const pi = makePi();
    register(pi as any, configWith([], [".env"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "edit", input: { path: "/p/.env" } }, c);
    assert.equal(r.block, true);
  });
  it("write not blocked when denyWrite empty", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"], []));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "write", input: { path: "/p/.env" } }, c);
    // denyRead doesn't apply to write
    assert.equal(r, undefined);
  });
});

describe("index.ts — tool_call for bash", () => {
  it("blocks bash command on match", async () => {
    const pi = makePi();
    register(pi as any, configWith([], [], ["rm -rf"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "bash", input: { command: "rm -rf /tmp" } }, c);
    assert.equal(r.block, true);
    assert.match(r.reason, /deny rule/);
    assert.match(r.reason, /rm -rf/);
  });
  it("blocks via operator split", async () => {
    const pi = makePi();
    register(pi as any, configWith([], [], ["sudo"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "bash", input: { command: "echo hi && sudo ls" } }, c);
    assert.equal(r.block, true);
  });
  it("not blocked when no match", async () => {
    const pi = makePi();
    register(pi as any, configWith([], [], ["rm -rf"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "bash", input: { command: "ls -la" } }, c);
    assert.equal(r, undefined);
  });
});

describe("index.ts — unknown tool + defensive wrapper", () => {
  it("unknown toolName → undefined (no opinion)", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"], [".env"], ["sudo"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "customTool", input: { anything: 1 } }, c);
    assert.equal(r, undefined);
  });
  it("malformed input (no path field) → undefined, no throw", async () => {
    const pi = makePi();
    register(pi as any, configWith([".env"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "read", input: {} }, c);
    assert.equal(r, undefined);
  });
  it("thrown matcher returns undefined and warns", async (t) => {
    const warn = t.mock.method(console, "warn");
    const pi = makePi();
    // bash.deny non-empty so the handler actually reaches the input access.
    register(pi as any, configWith([".env"], [], ["sudo"]));
    const { ctx: c } = ctx(false);
    const r = await pi.handlers.tool_call({ toolName: "read", input: { path: 42 as any } }, c);
    assert.equal(r, undefined);
    // input: null → .command access throws → caught, warn fires.
    const r2 = await pi.handlers.tool_call({ toolName: "bash", input: null as any }, c);
    assert.equal(r2, undefined);
    assert.ok(warn.mock.callCount() >= 1);
  });
});
