import { useEffect, useRef, useState } from "react";
import type { Note } from "../lib/api";

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
  const dirty = useRef(false);
  const area = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setTagText(note.tags.join(", "));
    dirty.current = false;
  }, [note.title, note.text, note.tags]);

  // Debounced autosave. Encryption is cheap enough not to need an explicit
  // save button to be the only path.
  useEffect(() => {
    if (isNew || !dirty.current) return;
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

  return (
    <section className="editor">
      <div className="editor-head">
        <input
          className="title"
          placeholder="Untitled"
          value={note.title}
          onChange={(e) => set("title", e.target.value)}
          disabled={isNew}
          spellCheck={false}
        />
        <div className="row">
          <button
            className={`pin-btn ${note.pinned ? "on" : ""}`}
            title="Pin"
            onClick={() => set("pinned", !note.pinned)}
          >
            {note.pinned ? "Pinned" : "Pin"}
          </button>
          <button onClick={onSave} disabled={isNew}>Save</button>
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
        disabled={isNew}
        spellCheck={false}
      />

      <textarea
        ref={area}
        className="body"
        placeholder="Start writing. Markdown works."
        value={note.text}
        onChange={(e) => set("text", e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Tab") {
            e.preventDefault();
            const el = area.current;
            if (!el) return;
            const s = el.selectionStart;
            const v = el.value;
            el.value = v.slice(0, s) + "  " + v.slice(el.selectionEnd);
            el.selectionStart = el.selectionEnd = s + 2;
            set("text", el.value);
          }
        }}
        disabled={isNew}
        spellCheck
      />
    </section>
  );
}