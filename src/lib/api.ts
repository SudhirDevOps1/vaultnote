import { invoke } from "@tauri-apps/api/core";

export type VaultStatus = "empty" | "locked" | "unlocked";

export interface Note {
  title: string;
  text: string;
  tags: string[];
  attachments: string[];
  pinned: boolean;
}

export interface NoteSummary {
  id: string;
  title: string;
  tags: string[];
  pinned: boolean;
  updated_at: number;
}

export const emptyNote = (): Note => ({
  title: "",
  text: "",
  tags: [],
  attachments: [],
  pinned: false,
});

/**
 * The complete IPC surface. Note what is missing: no call takes or returns
 * key material. The master key stays in Rust.
 */
export const api = {
  status: () => invoke<VaultStatus>("vault_status"),
  create: (password: string) => invoke<void>("create_vault", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),
  isUnlocked: () => invoke<boolean>("is_unlocked"),
  idleTimeoutSeconds: () => invoke<number>("idle_timeout_seconds"),

  list: () => invoke<NoteSummary[]>("list_notes"),
  trashed: () => invoke<NoteSummary[]>("list_trashed"),
  get: (id: string) => invoke<Note | null>("get_note", { id }),
  save: (id: string | null, note: Note) => invoke<string>("save_note", { id, note }),
  remove: (id: string) => invoke<void>("delete_note", { id }),
  restore: (id: string) => invoke<void>("restore_note", { id }),
  purge: (id: string) => invoke<void>("purge_note", { id }),
  search: (query: string) => invoke<NoteSummary[]>("search_notes", { query }),
  tags: () => invoke<[string, number][]>("list_tags"),
  changePassword: (newPassword: string) => invoke<void>("change_password", { newPassword }),
};