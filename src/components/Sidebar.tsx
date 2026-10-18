import type { NoteSummary } from "../lib/api";

interface Props {
  notes: NoteSummary[];
  activeId: string | null;
  query: string;
  showTrash: boolean;
  tagFilter: string | null;
  tags: [string, number][];
  onQuery: (q: string) => void;
  onTag: (t: string | null) => void;
  onToggleTrash: () => void;
  onSelect: (id: string) => void;
  onNew: () => void;
}

function when(ts: number): string {
  const diff = Date.now() - ts;
  const min = Math.floor(diff / 60_000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const d = Math.floor(hr / 24);
  if (d < 7) return `${d}d`;
  return new Date(ts).toLocaleDateString();
}

export default function Sidebar({
  notes,
  activeId,
  query,
  showTrash,
  tagFilter,
  tags,
  onQuery,
  onTag,
  onToggleTrash,
  onSelect,
  onNew,
}: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <input
          className="search"
          placeholder="Search…"
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          spellCheck={false}
        />
        <div className="sidebar-actions">
          <button onClick={onNew} title="New note">
            + New
          </button>
          <button
            onClick={onToggleTrash}
            className={showTrash ? "on" : ""}
            title="Trash"
          >
            Trash
          </button>
        </div>
      </div>

      {!showTrash && tags.length > 0 && (
        <div className="tagstrip">
          {tagFilter && (
            <button className="tag active" onClick={() => onTag(null)}>
              clear filter
            </button>
          )}
          {tags.map(([t, n]) => (
            <button
              key={t}
              className={`tag ${tagFilter === t ? "active" : ""}`}
              onClick={() => onTag(tagFilter === t ? null : t)}
            >
              {t} <span className="tag-n">{n}</span>
            </button>
          ))}
        </div>
      )}

      <div className="notelist">
        {notes.length === 0 && (
          <p className="empty">
            {showTrash ? "Trash is empty." : query ? "No matches." : "No notes yet."}
          </p>
        )}
        {notes.map((n) => (
          <button
            key={n.id}
            className={`note-row ${n.id === activeId ? "active" : ""}`}
            onClick={() => onSelect(n.id)}
          >
            <span className="note-title">
              {n.pinned && <span className="pin" title="Pinned">●</span>}
              {n.title || "Untitled"}
            </span>
            <span className="note-meta">
              {n.tags.slice(0, 2).join(", ")}
              {n.tags.length > 2 && ` +${n.tags.length - 2}`}
              <span className="dot">·</span>
              {when(n.updated_at)}
            </span>
          </button>
        ))}
      </div>
    </aside>
  );
}