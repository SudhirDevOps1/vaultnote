import { useEffect, useRef, useState } from "react";
import type { Note } from "../lib/api";
import { renderMarkdown, togglePrefix, toggleWrap, type WrapResult } from "../lib/markdown";

interface Props {
  note: Note;
  isNew: boolean;
  inTrash: boolean;
  onChange: (note: Note) => void;
  onSave: () => void;
  onDelete: () => void;
  onRestore: () => void;
  onPurge: () => void;
}

const AUTOSAVE_MS = 600;

type View = "write" | "split" | "read";

export default function Editor({
  note,
  isNew,
  inTrash,
  onChange,
  onSave,
  onDelete,
  onRestore,
  onPurge,
}: Props) {
  const [tagText, setTagText] = useState(note.tags.join(", "));
  const [view, setView] = useState<View>("split");
  const dirty = useRef(false);
  const area = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setTagText(note.tags.join(", "));
    dirty.current = false;
  }, [note.title, note.text, note.tags]);

  // Debounced autosave.
  //
  // `isNew` must NOT short-circuit this. A brand new note is exactly the one
  // that needs saving, and gating on it meant text could be typed but never
  // written to disk - there was no path to save a new note at all.
  //
  // App.save() already refuses to persist a note that is entirely empty, so
  // there is no second emptiness check needed here.
  useEffect(() => {
    if (!dirty.current) return;
    const t = setTimeout(onSave, AUTOSAVE_MS);
    return () => clearTimeout(t);
  }, [note.text, note.title]);

  function set<K extends keyof Note>(key: K, value: Note[K]) {
    dirty.current = true;
    onChange({ ...note, [key]: value });
  }

  function commitTags() {
    const tags = tagText
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    if (tags.join(",") !== note.tags.join(",")) set("tags", tags);
  }

  /**
   * Apply a transform to the textarea selection and put the caret back where
   * the user expects it.
   *
   * The value has to be written back into the DOM element directly before
   * React re-renders, otherwise the browser collapses the selection to the end
   * of the field and a second toolbar press lands in the wrong place.
   */
  function applyToSelection(fn: (v: string, s: number, e: number) => WrapResult) {
    const el = area.current;
    if (!el) return;
    const { text, selectionStart, selectionEnd } = fn(el.value, el.selectionStart, el.selectionEnd);
    set("text", text);
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(selectionStart, selectionEnd);
    });
  }

  function insertLine(prefix: string) {
    applyToSelection((v, s, e) => togglePrefix(v, s, e, prefix));
  }

  if (inTrash) {
    return (
      <section className="editor trash-view">
        <h2>{note.title || "Untitled"}</h2>
        <p className="muted">This note is in the trash.</p>
        <div className="row">
          <button className="primary" onClick={onRestore}>Restore</button>
          <button className="danger" onClick={onPurge}>Delete forever</button>
        </div>
      </section>
    );
  }

  const showWrite = view !== "read";
  const showRead = view !== "write";

  return (
    <section className="editor">
      <div className="editor-head">
        <input
          className="title"
          placeholder="Untitled"
          value={note.title}
          onChange={(e) => set("title", e.target.value)}
          spellCheck={false}
        />
        <div className="row">
          <div className="viewswitch" role="group" aria-label="Editor view">
            <button className={view === "write" ? "on" : ""} onClick={() => setView("write")} title="Editor only">Write</button>
            <button className={view === "split" ? "on" : ""} onClick={() => setView("split")} title="Editor and preview">Split</button>
            <button className={view === "read" ? "on" : ""} onClick={() => setView("read")} title="Preview only">Read</button>
          </div>
          <button
            className={`pin-btn ${note.pinned ? "on" : ""}`}
            title="Pin"
            onClick={() => set("pinned", !note.pinned)}
          >
            {note.pinned ? "Pinned" : "Pin"}
          </button>
          <button onClick={onSave}>Save</button>
          {/* Delete stays disabled for an unsaved note: there is nothing on
              disk to remove yet, and App.save has no id to delete by. */}
          <button className="danger" onClick={onDelete} disabled={isNew}>Delete</button>
        </div>
      </div>

      <input
        className="tags"
        placeholder="tags, comma separated"
        value={tagText}
        onChange={(e) => setTagText(e.target.value)}
        onBlur={commitTags}
        onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), commitTags())}
        spellCheck={false}
      />

      {showWrite && (
        <div className="toolbar" role="toolbar" aria-label="Formatting">
          <button title="Bold (Ctrl+B)" onMouseDown={(e) => e.preventDefault()} onClick={() => applyToSelection((v, s, e) => toggleWrap(v, s, e, "**"))}><b>B</b></button>
          <button title="Italic (Ctrl+I)" onMouseDown={(e) => e.preventDefault()} onClick={() => applyToSelection((v, s, e) => toggleWrap(v, s, e, "*"))}><i>I</i></button>
          <button title="Strikethrough" onMouseDown={(e) => e.preventDefault()} onClick={() => applyToSelection((v, s, e) => toggleWrap(v, s, e, "~~"))}><s>S</s></button>
          <button title="Inline code" onMouseDown={(e) => e.preventDefault()} onClick={() => applyToSelection((v, s, e) => toggleWrap(v, s, e, "`"))}><code>&lt;&gt;</code></button>
          <span className="tb-sep" />
          <button title="Heading 1" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("# ")}>H1</button>
          <button title="Heading 2" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("## ")}>H2</button>
          <button title="Bullet list" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("- ")}>&bull;&nbsp;List</button>
          <button title="Numbered list" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("1. ")}>1.</button>
          <button title="Checklist" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("- [ ] ")}>&#9744;</button>
          <button title="Quote" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("> ")}>&rdquo;</button>
          <span className="tb-sep" />
          <button title="Link (Ctrl+K)" onMouseDown={(e) => e.preventDefault()} onClick={() => applyToSelection((v, s, e) => toggleWrap(v, s, e, "[]()"))}>&#128279;</button>
          <button title="Code block" onMouseDown={(e) => e.preventDefault()} onClick={() => insertLine("```")}>&lt;/&gt;</button>
        </div>
      )}

      <div className={`panes ${view}`}>
        {showWrite && (
          <textarea
            ref={area}
            className="body"
            placeholder="Start writing. Markdown works - try **bold** or # heading."
            value={note.text}
            onChange={(e) => set("text", e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Tab") {
                e.preventDefault();
                const el = area.current;
                if (!el) return;
                const s = el.selectionStart;
                const v = el.value;
                const next = v.slice(0, s) + "  " + v.slice(el.selectionEnd);
                set("text", next);
                requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2));
              } else if (e.ctrlKey || e.metaKey) {
                const key = e.key.toLowerCase();
                if (key === "b" || key === "i" || key === "k") {
                  e.preventDefault();
                  applyToSelection((v, s, en) =>
                    toggleWrap(v, s, en, key === "b" ? "**" : key === "i" ? "*" : "[]()"),
                  );
                }
              }
            }}
            spellCheck
          />
        )}
        {showRead && (
          <div
            className="preview markdown-body"
            // Content is decrypted from the user's own vault; see the note in
            // lib/markdown.ts for why this is not sanitised.
            dangerouslySetInnerHTML={{ __html: renderMarkdown(note.text) }}
          />
        )}
      </div>
    </section>
  );
}