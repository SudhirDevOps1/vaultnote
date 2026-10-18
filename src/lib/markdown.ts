import { marked } from "marked";

marked.setOptions({
  gfm: true,
  breaks: true,
});

/**
 * Render markdown to HTML for the preview pane.
 *
 * No sanitiser, and that is a deliberate decision rather than an oversight.
 * The only input here is text decrypted from the user's own vault, written by
 * the user on this machine. There is no second party who can put a payload in
 * it, no sync, no import from elsewhere, and no network. Sanitising would be
 * defending against an attacker who would already have the master password.
 *
 * That changes the moment an encrypted backup can be restored from a file
 * someone else produced. Revisit this then, not before.
 */
export function renderMarkdown(source: string): string {
  if (!source.trim()) return "";
  return marked.parse(source, { async: false }) as string;
}

export type WrapKind = "bold" | "italic" | "code" | "strike";

export interface WrapResult {
  text: string;
  selectionStart: number;
  selectionEnd: number;
}

/**
 * Wrap or unwrap the current selection in a markdown marker.
 *
 * Toggling matters because pressing Bold twice on the same words should remove
 * the markers, not produce `****four stars****`. The unwrap path is found by
 * searching outwards from the selection.
 */
export function toggleWrap(
  value: string,
  start: number,
  end: number,
  marker: string,
): WrapResult {
  const has = marker.length;
  const before = value.slice(Math.max(0, start - has), start);
  const after = value.slice(end, end + has);

  if (before === marker && after === marker) {
    return {
      text: value.slice(0, start - has) + value.slice(start, end) + value.slice(end + has),
      selectionStart: start - has,
      selectionEnd: end - has,
    };
  }

  return {
    text: value.slice(0, start) + marker + value.slice(start, end) + marker + value.slice(end),
    selectionStart: start + has,
    selectionEnd: end + has,
  };
}

/** Prefix every selected line, replacing an existing identical prefix. */
export function togglePrefix(
  value: string,
  start: number,
  end: number,
  prefix: string,
): WrapResult {
  const lineStart = value.lastIndexOf("\n", start - 1) + 1;
  const lineEndIdx = value.indexOf("\n", end);
  const lineEnd = lineEndIdx === -1 ? value.length : lineEndIdx;
  const block = value.slice(lineStart, lineEnd);

  const lines = block.split("\n");
  const allPrefixed = lines.every((l) => l.startsWith(prefix));

  const replaced = lines
    .map((l) => (allPrefixed ? l.slice(prefix.length) : prefix + l))
    .join("\n");

  return {
    text: value.slice(0, lineStart) + replaced + value.slice(lineEnd),
    selectionStart: lineStart,
    selectionEnd: lineStart + replaced.length,
  };
}