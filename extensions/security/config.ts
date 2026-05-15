import { existsSync, readFileSync } from "node:fs";
import { join as joinPath } from "node:path";

// mountMask and isolateDirs are host-side only: the container runtime reads
// them before pi starts. The extension parses them so the schema stays
// accurate and writers get feedback, but never acts on them at runtime.
export interface SecurityConfig {
  enabled: boolean;
  filesystem: {
    denyRead: string[];
    denyWrite: string[];
    mountMask: string[];
    isolateDirs: string[];
  };
  bash: { deny: string[] };
}

export interface PartialConfig {
  enabled: boolean | undefined;
  filesystem: {
    denyRead: string[];
    denyWrite: string[];
    mountMask: string[];
    isolateDirs: string[];
  };
  bash: { deny: string[] };
}

const EMPTY_PARTIAL: PartialConfig = {
  enabled: undefined,
  filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
  bash: { deny: [] },
};

function clone(p: PartialConfig): PartialConfig {
  return {
    enabled: p.enabled,
    filesystem: {
      denyRead: [...p.filesystem.denyRead],
      denyWrite: [...p.filesystem.denyWrite],
      mountMask: [...p.filesystem.mountMask],
      isolateDirs: [...p.filesystem.isolateDirs],
    },
    bash: { deny: [...p.bash.deny] },
  };
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

// Missing file → empty partial. Parse error → warn + empty. Never throws.
export function loadFile(path: string): PartialConfig {
  if (!existsSync(path)) return clone(EMPTY_PARTIAL);
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (err) {
    console.warn(`[security] failed to read ${path}: ${(err as Error).message}`);
    return clone(EMPTY_PARTIAL);
  }
  const src = path.endsWith(".jsonc") ? stripJsonComments(raw) : raw;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(src) as Record<string, unknown>;
  } catch (err) {
    console.warn(`[security] failed to parse ${path}: ${(err as Error).message}`);
    return clone(EMPTY_PARTIAL);
  }
  const fs = (parsed.filesystem ?? {}) as Record<string, unknown>;
  const bash = (parsed.bash ?? {}) as Record<string, unknown>;
  return {
    enabled: typeof parsed.enabled === "boolean" ? parsed.enabled : undefined,
    filesystem: {
      denyRead: asStringArray(fs.denyRead),
      denyWrite: asStringArray(fs.denyWrite),
      mountMask: asStringArray(fs.mountMask),
      isolateDirs: asStringArray(fs.isolateDirs),
    },
    bash: { deny: asStringArray(bash.deny) },
  };
}

export interface LoadOptions {
  // Directory that holds security.jsonc / security.json. Typically the
  // extensions root (the parent of this extension's package folder).
  dir: string;
}

// Tries security.jsonc first, falls back to security.json. Returns the
// first candidate (even if absent) so callers can show the expected path.
export function resolveConfigPath(dir: string): string {
  const candidates = [joinPath(dir, "security.jsonc"), joinPath(dir, "security.json")];
  return candidates.find(existsSync) ?? candidates[0];
}

// Loads a single security.{jsonc,json} from `dir`. Missing file → EMPTY defaults.
export function loadConfig(opts: LoadOptions): SecurityConfig {
  const p = loadFile(resolveConfigPath(opts.dir));
  return {
    enabled: p.enabled ?? true,
    filesystem: {
      denyRead: [...p.filesystem.denyRead],
      denyWrite: [...p.filesystem.denyWrite],
      mountMask: [...p.filesystem.mountMask],
      isolateDirs: [...p.filesystem.isolateDirs],
    },
    bash: { deny: [...p.bash.deny] },
  };
}

export const EMPTY: SecurityConfig = {
  enabled: true,
  filesystem: { denyRead: [], denyWrite: [], mountMask: [], isolateDirs: [] },
  bash: { deny: [] },
};

// Walks the input char by char, toggling an in-string flag so // and /* */ inside JSON strings stay intact.
export function stripJsonComments(src: string): string {
  let out = "";
  let i = 0;
  let inStr = false;
  let strQuote = "";
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\" && i + 1 < src.length) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (c === strQuote) {
        inStr = false;
        strQuote = "";
      }
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = true;
      strQuote = c;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && n === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}
