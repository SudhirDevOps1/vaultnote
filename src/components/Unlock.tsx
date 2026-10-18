import { useState, type FormEvent } from "react";
import { api } from "../lib/api";

interface Props {
  mode: "create" | "unlock";
  onDone: () => void;
}

export default function Unlock({ mode, onDone }: Props) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const creating = mode === "create";
  const tooShort = password.length < 8;
  const mismatch = creating && confirm.length > 0 && confirm !== password;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (creating && (tooShort || mismatch)) return;
    setBusy(true);
    setError(null);
    try {
      if (creating) await api.create(password);
      else await api.unlock(password);
      onDone();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <form className="gate-card" onSubmit={submit}>
        <div className="gate-mark" aria-hidden="true" />
        <h1>Vaultnote</h1>

        {creating ? (
          <>
            <p className="gate-sub">
              Choose a master password. It encrypts everything on this
              machine — there is no server, and no way to recover it.
            </p>
          </>
        ) : (
          <p className="gate-sub">Enter your master password to unlock.</p>
        )}

        <label className="field">
          <span>Master password</span>
          <input
            type="password"
            value={password}
            autoFocus
            autoComplete={creating ? "new-password" : "current-password"}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </label>

        {creating && (
          <label className="field">
            <span>Confirm password</span>
            <input
              type="password"
              value={confirm}
              autoComplete="new-password"
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
          </label>
        )}

        {creating && tooShort && password.length > 0 && (
          <p className="hint warn">At least 8 characters.</p>
        )}
        {mismatch && <p className="hint warn">Passwords do not match.</p>}
        {error && <p className="hint error">{error}</p>}

        <button
          type="submit"
          className="primary"
          disabled={busy || (creating && (tooShort || mismatch))}
        >
          {busy
            ? creating
              ? "Deriving key…"
              : "Unlocking…"
            : creating
              ? "Create vault"
              : "Unlock"}
        </button>

        {creating && <p className="gate-foot">Derivation takes a moment. That is the point.</p>}
      </form>
    </div>
  );
}