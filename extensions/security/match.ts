import { basename, isAbsolute, join as joinPath, resolve } from "node:path";
import { homedir } from "node:os";

export interface PathMatch {
  matched: boolean;
  rule?: string;
}

// Supports *, **, ?. All other regex metachars are escaped.
export function globToRegex(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\x00")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/\x00/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function expandTilde(p: string): string {
  return p === "~" ? homedir() : p.startsWith("~/") ? joinPath(homedir(), p.slice(2)) : p;
}

export function matchesPath(
  target: string,
  patterns: string[],
  opts: { cwd?: string } = {},
): PathMatch {
  const cwd = opts.cwd ?? process.cwd();
  const absTarget = isAbsolute(target) ? target : resolve(cwd, target);
  const base = basename(absTarget);

  for (const pattern of patterns) {
    const expanded = expandTilde(pattern);
    const isBasenameOnly = !expanded.includes("/") || /^[^/]+\/$/.test(expanded);

    if (isBasenameOnly) {
      const trimmed = expanded.replace(/\/$/, "");
      const re = globToRegex(trimmed);
      // Trailing-slash basename pattern (e.g. "node_modules/"): gitignore semantics —
      // match the dir and everything under it. Check every path segment.
      const isDirOnly = expanded.endsWith("/");
      const segments = isDirOnly ? absTarget.split("/").filter(Boolean) : [base];
      let matched = false;
      for (const seg of segments) {
        if (re.test(seg)) {
          matched = true;
          break;
        }
      }
      if (matched) return { matched: true, rule: pattern };
      continue;
    }

    const isDirPattern = expanded.endsWith("/");
    const abs = isAbsolute(expanded) ? expanded : resolve(cwd, expanded);

    if (isDirPattern) {
      const literal = abs.replace(/\/$/, "").replace(/[.+^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(`^${literal}(/.*)?$`);
      if (re.test(absTarget)) return { matched: true, rule: pattern };
    } else {
      if (globToRegex(abs).test(absTarget)) return { matched: true, rule: pattern };
    }
  }
  return { matched: false };
}

export interface BashMatch {
  matched: boolean;
  rule?: string;
}

function tokens(s: string): string[] {
  return s.trim().split(/\s+/).filter(Boolean);
}

function tokenPrefixMatch(segment: string, patternTokens: string[]): boolean {
  const cmd = tokens(segment);
  if (patternTokens.length === 0 || cmd.length < patternTokens.length) return false;
  for (let i = 0; i < patternTokens.length; i++) {
    if (cmd[i] !== patternTokens[i]) return false;
  }
  return true;
}

// Best-effort splitter. Splits on |, ||, &&, ;, and extracts $(...) contents as extra segments.
// Not a real shell parser — quoted strings may tokenize imperfectly; v1 limitation.
export function splitCommand(cmd: string): string[] {
  const subshells: string[] = [];
  const withoutSubshells = cmd.replace(/\$\(([^)]*)\)/g, (_, inner: string) => {
    subshells.push(inner);
    return " ";
  });
  const segments: string[] = [];
  segments.push(...withoutSubshells.split(/\s*(?:\|{1,2}|&&|;)\s*/));
  segments.push(...subshells);
  return segments.map((s) => s.trim()).filter(Boolean);
}

export function matchesBash(command: string, patterns: string[]): BashMatch {
  const segments = splitCommand(command);
  for (const pattern of patterns) {
    if (pattern.startsWith("re:")) {
      const src = pattern.slice(3);
      let re: RegExp;
      try {
        re = new RegExp(src);
      } catch (err) {
        console.warn(`[security] invalid regex in bash rule ${JSON.stringify(pattern)}: ${(err as Error).message}`);
        continue;
      }
      if (re.test(command)) return { matched: true, rule: pattern };
      continue;
    }
    const patTokens = tokens(pattern);
    if (patTokens.length === 0) continue;
    for (const seg of segments) {
      if (tokenPrefixMatch(seg, patTokens)) return { matched: true, rule: pattern };
    }
  }
  return { matched: false };
}
