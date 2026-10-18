import { useCallback, useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import Unlock from "./components/Unlock";
import Sidebar from "./components/Sidebar";
import Editor from "./components/Editor";
import { api, emptyNote, type Note, type NoteSummary, type VaultStatus } from "./lib/api";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [notes, setNotes] = useState<NoteSummary[]>([]);
  const [tags, setTags] = useState<[string, number][]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [note, setNote] = useState<Note>(emptyNote());
  const [isNew, setIsNew] = useState(false);
  const [query, setQuery] = useState("");
  const [showTrash, setShowTrash] = useState(false);
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [trashed, setTrashed] = useState<NoteSummary[]>([]);
  const [searched, setSearched] = useState<NoteSummary[]>([]);

  // ---- lifecycle ---------------------------------------------------------

  const refresh = useCallback(async () => {
    const [list, t] = await Promise.all([api.list(), api.tags()]);
    setNotes(list);
    setTags(t);
  }, []);

  useEffect(() => {
    api.status().then(setStatus).catch((e) => setError(String(e)));
  }, []);

  // Everything the webview is holding that came out of the vault. Rust drops
  // the root key the moment the idle ticker fires; the decrypted note body and
  // the note *titles* sitting in React state have to be dropped at the same
  // moment, or the process keeps plaintext it is no longer entitled to hold.
  // The explicit Lock button already did this; the idle-lock event did not.
  const clearWorkspace = useCallback(() => {
    setNotes([]);
    setTags([]);
    setTrashed([]);
    setSearched([]);
    setActiveId(null);
    setNote(emptyNote());
    setIsNew(false);
    setTagFilter(null);
    setQuery("");
    setShowTrash(false);
  }, []);

  // Rust tells us when the idle ticker dropped the key.
  useEffect(() => {
    const un = listen("vault-locked", () => {
      setStatus("locked");
      clearWorkspace();
    });
    return () => {
      un.then((f) => f()).catch(() => {});
    };
  }, [clearWorkspace]);

  const onUnlocked = useCallback(async () => {
    setStatus("unlocked");
    setError(null);
    await refresh();
  }, [refresh]);

  // ---- loading a note ----------------------------------------------------

  const open = useCallback(async (id: string) => {
    try {
      const n = await api.get(id);
      if (n) {
        setNote(n);
        setIsNew(false);
        setActiveId(id);
      }
    } catch (e) {
      setError(String(e));
    }
  }, []);

  // ---- writes ------------------------------------------------------------

  const persist = useCallback(
    async (target: string | null, body: Note) => {
      const id = await api.save(target, body);
      if (target === null) {
        setActiveId(id);
        setIsNew(false);
      }
      await refresh();
      return id;
    },
    [refresh],
  );

  const newNote = useCallback(() => {
    setNote(emptyNote());
    setActiveId(null);
    setIsNew(true);
    setShowTrash(false);
  }, []);

  const save = useCallback(async () => {
    if (isNew && !note.title.trim() && !note.text.trim()) return;
    try {
      await persist(activeId, note);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [activeId, isNew, note, persist]);

  const del = useCallback(async () => {
    if (!activeId) return;
    await api.remove(activeId).catch((e) => setError(String(e)));
    setActiveId(null);
    setIsNew(false);
    await refresh();
  }, [activeId, refresh]);

  const restore = useCallback(async () => {
    if (!activeId) return;
    await api.restore(activeId).catch((e) => setError(String(e)));
    await refresh();
  }, [activeId, refresh]);

  const purge = useCallback(async () => {
    if (!activeId) return;
    await api.purge(activeId).catch((e) => setError(String(e)));
    setActiveId(null);
    await refresh();
  }, [activeId, refresh]);

  const lock = useCallback(async () => {
    await api.lock();
    setStatus("locked");
    clearWorkspace();
  }, [clearWorkspace]);

  // ---- derived -----------------------------------------------------------

  useEffect(() => {
    if (!showTrash) return;
    api.trashed().then(setTrashed).catch((e) => setError(String(e)));
  }, [showTrash, notes]);

  useEffect(() => {
    if (!showTrash) return;
    if (activeId) {
      const found = trashed.find((n) => n.id === activeId);
      if (found) {
        api.get(activeId).then((n) => n && setNote(n)).catch(() => {});
        setIsNew(false);
      }
    }
  }, [trashed, activeId, showTrash]);

  useEffect(() => {
    const t = setTimeout(() => {
      if (showTrash) return;
      api.search(query).then(setSearched).catch((e) => setError(String(e)));
    }, 200);
    return () => clearTimeout(t);
  }, [query, notes, showTrash]);

  const listed = useMemo(() => {
    const base = showTrash ? trashed : searched;
    return tagFilter ? base.filter((n) => n.tags.includes(tagFilter)) : base;
  }, [searched, trashed, showTrash, tagFilter]);

  // ---- render ------------------------------------------------------------

  if (status === null) {
    return <div className="gate"><div className="gate-card"><p className="muted">Loading…</p></div></div>;
  }

  if (status !== "unlocked") {
    return <Unlock mode={status === "empty" ? "create" : "unlock"} onDone={onUnlocked} />;
  }

  const inTrash = showTrash && !!activeId;

  return (
    <div className="shell">
      <Sidebar
        notes={listed}
        activeId={activeId}
        query={query}
        showTrash={showTrash}
        tagFilter={tagFilter}
        tags={tags}
        onQuery={(q) => { setQuery(q); setShowTrash(false); }}
        onTag={setTagFilter}
        onToggleTrash={() => { setShowTrash((v) => !v); setActiveId(null); setIsNew(false); }}
        onSelect={open}
        onNew={newNote}
      />

      {activeId || isNew ? (
        <Editor
          note={note}
          isNew={isNew}
          inTrash={inTrash}
          onChange={setNote}
          onSave={save}
          onDelete={del}
          onRestore={restore}
          onPurge={purge}
        />
      ) : (
        <section className="editor placeholder">
          <p className="muted">Select a note, or press <kbd>+ New</kbd>.</p>
          {error && <p className="hint error">{error}</p>}
        </section>
      )}

      <footer className="statusbar">
        <span>{notes.length} notes</span>
        {error && <span className="err">{error}</span>}
        <button onClick={lock}>Lock now</button>
      </footer>
    </div>
  );
}