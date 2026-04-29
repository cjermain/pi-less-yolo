import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { join as joinPath } from "node:path";
import { loadConfig, resolveConfigPath, type SecurityConfig } from "./config.ts";
import { matchesPath, matchesBash } from "./match.ts";

// The exported signature takes an optional injected config for tests; in production loaded from disk.
export default function register(pi: ExtensionAPI, injected?: SecurityConfig) {
  // security.{jsonc,json} sits next to this extension's package folder.
  const configDir = joinPath(import.meta.dirname, "..");
  const configPath = resolveConfigPath(configDir);
  const config = injected ?? loadConfig({ dir: configDir });

  function summary(): string {
    if (!config.enabled) return "🔓 security disabled";
    const parts: string[] = [];
    if (config.filesystem.denyRead.length) parts.push(`${config.filesystem.denyRead.length} read`);
    if (config.filesystem.denyWrite.length) parts.push(`${config.filesystem.denyWrite.length} write`);
    if (config.bash.deny.length) parts.push(`${config.bash.deny.length} bash`);
    return parts.length ? `🔒 security: ${parts.join(", ")}` : "🔒 security: no rules";
  }

  pi.on("session_start", (_event, ctx) => {
    if (!ctx.hasUI) return;
    const text = summary();
    // Persistent yellow footer status so the user always sees security is active.
    ctx.ui.setStatus("security", ctx.ui.theme.fg("accent", text));
    ctx.ui.notify(text, "info");
  });

  pi.registerCommand("security", {
    description: "Show security rules and config file path",
    handler: async (_args, ctx) => {
      const lines: string[] = [];
      lines.push(summary());
      lines.push(`config: ${configPath}`);
      if (config.filesystem.denyRead.length) {
        lines.push(`\ndenyRead (${config.filesystem.denyRead.length}):`);
        for (const r of config.filesystem.denyRead) lines.push(`  • ${r}`);
      }
      if (config.filesystem.denyWrite.length) {
        lines.push(`\ndenyWrite (${config.filesystem.denyWrite.length}):`);
        for (const r of config.filesystem.denyWrite) lines.push(`  • ${r}`);
      }
      if (config.bash.deny.length) {
        lines.push(`\nbash.deny (${config.bash.deny.length}):`);
        for (const r of config.bash.deny) lines.push(`  • ${r}`);
      }
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  if (!config.enabled) return;

  const READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
  const WRITE_TOOLS = new Set(["write", "edit"]);

  pi.on("tool_call", async (event, ctx) => {
    try {
      const { toolName } = event;

      if (READ_TOOLS.has(toolName)) {
        if (config.filesystem.denyRead.length === 0) return undefined;
        const path = (event.input as { path?: string }).path;
        if (typeof path !== "string") return undefined;
        const m = matchesPath(path, config.filesystem.denyRead);
        if (m.matched) {
          if (ctx.hasUI) ctx.ui.notify(`🚫 Blocked ${toolName}: ${path}\n  rule: ${m.rule}`, "warning");
          return { block: true, reason: `"${path}" matches denyRead rule: ${m.rule}` };
        }
        return undefined;
      }

      if (WRITE_TOOLS.has(toolName)) {
        if (config.filesystem.denyWrite.length === 0) return undefined;
        const path = (event.input as { path?: string }).path;
        if (typeof path !== "string") return undefined;
        const m = matchesPath(path, config.filesystem.denyWrite);
        if (m.matched) {
          if (ctx.hasUI) ctx.ui.notify(`🚫 Blocked ${toolName}: ${path}\n  rule: ${m.rule}`, "warning");
          return { block: true, reason: `"${path}" matches denyWrite rule: ${m.rule}` };
        }
        return undefined;
      }

      if (toolName === "bash") {
        if (config.bash.deny.length === 0) return undefined;
        const command = (event.input as { command?: string }).command;
        if (typeof command !== "string") return undefined;
        const m = matchesBash(command, config.bash.deny);
        if (m.matched) {
          if (ctx.hasUI) ctx.ui.notify(`🚫 Blocked bash\n  rule: ${m.rule}`, "warning");
          return { block: true, reason: `bash command matches deny rule: ${m.rule}` };
        }
        return undefined;
      }

      return undefined;
    } catch (err) {
      console.warn(`[security] handler error for ${event.toolName}:`, err);
      return undefined;
    }
  });
}
