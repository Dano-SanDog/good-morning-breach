import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

export type CatalogCategory = {
  id: string;
  name: string;
  enabled: boolean;
  storyCount: number;
};
export type CatalogSource = {
  id: string;
  name: string;
  address: string;
  format: string;
  licenseName: string;
  licenseUrl: string;
  permittedUse: string;
  attribution: string;
  contentPolicy: string;
  rightsClass: string;
  pollIntervalSeconds: number;
  enabled: boolean;
  requireCompleteTitle: boolean;
  storyCount: number;
};

export const sourceFormats = [
  "rss",
  "cisa_kev_json",
  "github_advisories_json",
  "nvd_json",
  "hibp_breaches_json",
  "hacker_news_json",
] as const;
export const contentPolicies = [
  ["headline_link", "Headline and link only"],
  ["verbatim_excerpt", "Verbatim excerpt"],
  ["system_summary", "System summary"],
  ["full_text", "Full text"],
] as const;
export const rightsClasses = [
  ["licensed", "Licensed for the use recorded above"],
  ["all_rights_reserved", "All rights reserved (headline, source name, and link only)"],
] as const;
const fallbackCategoryID = "other";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseCatalogCategories(value: unknown): CatalogCategory[] | null {
  if (!isRecord(value) || !Array.isArray(value.categories)) return null;
  const out: CatalogCategory[] = [];
  for (const item of value.categories) {
    if (!isRecord(item) || typeof item.id !== "string" || typeof item.name !== "string" ||
        typeof item.enabled !== "boolean" || typeof item.storyCount !== "number") return null;
    out.push({ id: item.id, name: item.name, enabled: item.enabled, storyCount: item.storyCount });
  }
  return out;
}

export function parseCatalogSources(value: unknown): CatalogSource[] | null {
  if (!isRecord(value) || !Array.isArray(value.sources)) return null;
  const out: CatalogSource[] = [];
  for (const item of value.sources) {
    if (!isRecord(item) || typeof item.id !== "string" || typeof item.name !== "string" ||
        typeof item.address !== "string" || typeof item.format !== "string" ||
        typeof item.licenseName !== "string" || typeof item.licenseUrl !== "string" ||
        typeof item.permittedUse !== "string" || typeof item.attribution !== "string" ||
        typeof item.contentPolicy !== "string" || typeof item.rightsClass !== "string" || typeof item.pollIntervalSeconds !== "number" ||
        typeof item.enabled !== "boolean" || typeof item.requireCompleteTitle !== "boolean" ||
        typeof item.storyCount !== "number") return null;
    out.push({
      id: item.id, name: item.name, address: item.address, format: item.format,
      licenseName: item.licenseName, licenseUrl: item.licenseUrl, permittedUse: item.permittedUse,
      attribution: item.attribution, contentPolicy: item.contentPolicy, rightsClass: item.rightsClass,
      pollIntervalSeconds: item.pollIntervalSeconds, enabled: item.enabled,
      requireCompleteTitle: item.requireCompleteTitle, storyCount: item.storyCount,
    });
  }
  return out;
}

export function hasLicenceRecord(source: Pick<CatalogSource, "licenseName" | "licenseUrl">): boolean {
  return source.licenseName.trim() !== "" && source.licenseUrl.trim() !== "";
}

export function sourceHost(address: string): string {
  try {
    return new URL(address).hostname;
  } catch {
    return "";
  }
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const payload: unknown = await response.json();
    if (isRecord(payload) && typeof payload.error === "string") return payload.error;
  } catch {
    return "The request could not be completed.";
  }
  return "The request could not be completed.";
}

function send(path: string, method: "POST" | "PATCH" | "DELETE", body: Record<string, unknown> = {}) {
  return fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-GMB-CSRF": "1" },
    body: JSON.stringify(body),
  });
}

type SourceDraft = {
  name: string;
  address: string;
  format: string;
  licenseName: string;
  licenseUrl: string;
  permittedUse: string;
  attribution: string;
  contentPolicy: string;
  rightsClass: string;
  pollIntervalHours: string;
  enabled: boolean;
  requireCompleteTitle: boolean;
};

const emptyDraft: SourceDraft = {
  name: "", address: "", format: "rss", licenseName: "", licenseUrl: "", permittedUse: "",
  attribution: "", contentPolicy: "headline_link", rightsClass: "licensed", pollIntervalHours: "1", enabled: false,
  requireCompleteTitle: false,
};

function draftFromSource(source: CatalogSource): SourceDraft {
  return {
    name: source.name, address: source.address, format: source.format, licenseName: source.licenseName,
    licenseUrl: source.licenseUrl, permittedUse: source.permittedUse, attribution: source.attribution,
    contentPolicy: source.contentPolicy, rightsClass: source.rightsClass, pollIntervalHours: String(source.pollIntervalSeconds / 3600),
    enabled: source.enabled, requireCompleteTitle: source.requireCompleteTitle,
  };
}

export function sourceRequestBody(draft: SourceDraft): Record<string, unknown> {
  return {
    name: draft.name, address: draft.address, format: draft.format, licenseName: draft.licenseName,
    licenseUrl: draft.licenseUrl, permittedUse: draft.permittedUse, attribution: draft.attribution,
    contentPolicy: draft.rightsClass === "all_rights_reserved" ? "headline_link" : draft.contentPolicy,
    rightsClass: draft.rightsClass, pollIntervalSeconds: Math.round(Number(draft.pollIntervalHours) * 3600),
    enabled: draft.enabled, requireCompleteTitle: draft.requireCompleteTitle,
  };
}

type Pending = { kind: "category" | "source"; id: string; name: string; consequence: string };

function ConfirmDialog({ pending, busy, onCancel, onConfirm }: {
  pending: Pending;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => cancelRef.current?.focus(), []);
  return (
    <div className="dialog-scrim">
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"
        onKeyDown={(event) => { if (event.key === "Escape") onCancel(); }}>
        <h3 id="catalog-dialog-title">Delete {pending.name}?</h3>
        <p>{pending.consequence}</p>
        <div className="dialog-actions">
          <button type="button" className="secondary-button" ref={cancelRef} onClick={onCancel}>Cancel</button>
          <button type="button" className="destructive-button" disabled={busy} onClick={onConfirm}>
            Delete {pending.kind}
          </button>
        </div>
      </div>
    </div>
  );
}

export function CatalogAdmin({ onChanged }: { onChanged?: () => void }) {
  const [categories, setCategories] = useState<CatalogCategory[] | null>(null);
  const [sources, setSources] = useState<CatalogSource[] | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [newCategory, setNewCategory] = useState("");
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [editingID, setEditingID] = useState<string | null>(null);
  const [draft, setDraft] = useState<SourceDraft>(emptyDraft);
  const [formOpen, setFormOpen] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);

  const load = useCallback(async () => {
    const [categoryResponse, sourceResponse] = await Promise.all([
      fetch("/api/admin/categories", { credentials: "same-origin" }),
      fetch("/api/admin/source-records", { credentials: "same-origin" }),
    ]);
    if (!categoryResponse.ok) throw new Error(await errorMessage(categoryResponse));
    if (!sourceResponse.ok) throw new Error(await errorMessage(sourceResponse));
    const loadedCategories = parseCatalogCategories(await categoryResponse.json());
    const loadedSources = parseCatalogSources(await sourceResponse.json());
    if (!loadedCategories || !loadedSources) throw new Error("The server returned invalid catalog data.");
    setCategories(loadedCategories);
    setSources(loadedSources);
  }, []);

  useEffect(() => {
    load().catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Could not load the catalog."));
  }, [load]);

  async function run(action: () => Promise<Response>, failure: string): Promise<boolean> {
    setBusy(true);
    setMessage("");
    try {
      const response = await action();
      if (!response.ok) throw new Error(await errorMessage(response));
      await load();
      onChanged?.();
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : failure);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateCategory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (await run(() => send("/api/admin/categories", "POST", { name: newCategory }), "Could not add the category.")) {
      setNewCategory("");
    }
  }

  async function handleRename(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!renaming) return;
    if (await run(() => send(`/api/admin/categories/${encodeURIComponent(renaming.id)}`, "PATCH", { name: renaming.name }), "Could not rename the category.")) {
      setRenaming(null);
    }
  }

  async function handleSaveSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = sourceRequestBody(draft);
    const ok = editingID === null
      ? await run(() => send("/api/admin/sources", "POST", body), "Could not add the source.")
      : await run(() => send(`/api/admin/sources/${encodeURIComponent(editingID)}`, "PATCH", body), "Could not save the source.");
    if (ok) {
      setFormOpen(false);
      setEditingID(null);
      setDraft(emptyDraft);
    }
  }

  async function confirmDelete() {
    if (!pending) return;
    const base = pending.kind === "category" ? "/api/admin/categories/" : "/api/admin/sources/";
    const target = pending;
    await run(() => send(base + encodeURIComponent(target.id), "DELETE"), "Could not delete the record.");
    setPending(null);
  }

  return (
    <section className="admin-panel" aria-labelledby="catalog-heading">
      <div className="dashboard-heading">
        <div>
          <h2 id="catalog-heading">Categories and sources</h2>
          <p className="muted">Changes to sources apply at the next collection. Disable a record that has stories instead of deleting it.</p>
        </div>
      </div>
      {message && <p className="form-error" role="alert">Error: {message}</p>}

      <h3 className="audit-heading">Categories</h3>
      <form className="account-create-form" onSubmit={handleCreateCategory}>
        <label>
          New category name
          <input maxLength={80} required value={newCategory} onChange={(event) => setNewCategory(event.target.value)} />
        </label>
        <button type="submit" className="primary-button" disabled={busy}>Add category</button>
      </form>
      {categories === null ? <p className="muted">Loading categories…</p> : (
        <div className="admin-table-scroll">
          <table className="admin-table">
            <thead><tr><th scope="col">Category</th><th scope="col">Status</th><th scope="col">Stories</th><th scope="col">Actions</th></tr></thead>
            <tbody>
              {categories.map((category) => {
                const protectedCategory = category.id === fallbackCategoryID;
                return (
                  <tr key={category.id}>
                    <th scope="row">
                      {renaming?.id === category.id ? (
                        <form className="inline-form" onSubmit={handleRename}>
                          <input aria-label={`New name for ${category.name}`} maxLength={80} required value={renaming.name}
                            onChange={(event) => setRenaming({ id: category.id, name: event.target.value })} />
                          <button type="submit" className="table-button" disabled={busy}>Save</button>
                          <button type="button" className="table-button" onClick={() => setRenaming(null)}>Cancel</button>
                        </form>
                      ) : category.name}
                    </th>
                    <td>{category.enabled ? "Enabled" : "Disabled"}</td>
                    <td>{category.storyCount}</td>
                    <td className="admin-actions">
                      <button type="button" className="table-button" disabled={busy}
                        onClick={() => setRenaming({ id: category.id, name: category.name })}>Rename</button>
                      <button type="button" className="table-button" disabled={busy || (protectedCategory && category.enabled)}
                        onClick={() => void run(() => send(`/api/admin/categories/${encodeURIComponent(category.id)}`, "PATCH", { enabled: !category.enabled }), "Could not update the category.")}>
                        {category.enabled ? "Disable" : "Enable"}
                      </button>
                      <button type="button" className="table-button danger-button" disabled={busy || protectedCategory}
                        onClick={() => setPending({
                          kind: "category", id: category.id, name: category.name,
                          consequence: category.storyCount > 0
                            ? `${category.storyCount} stories use this category, so it cannot be deleted. Disable it instead.`
                            : "This can't be undone.",
                        })}>Delete</button>
                      {protectedCategory && <span className="muted">Fallback category: it cannot be disabled or deleted.</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="audit-heading">Data sources</h3>
      {!formOpen && (
        <button type="button" className="primary-button" disabled={busy}
          onClick={() => { setDraft(emptyDraft); setEditingID(null); setFormOpen(true); }}>Add source</button>
      )}
      {formOpen && (
        <form className="source-form" onSubmit={handleSaveSource} aria-label={editingID === null ? "Add source" : "Edit source"}>
          <label>Name<input maxLength={120} required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label>
          <label>Feed address (HTTPS)<input type="url" maxLength={2048} required value={draft.address} onChange={(event) => setDraft({ ...draft, address: event.target.value })} /></label>
          <label>Format<select value={draft.format} onChange={(event) => setDraft({ ...draft, format: event.target.value })}>
            {sourceFormats.map((format) => <option key={format} value={format}>{format}</option>)}
          </select></label>
          <label>License or terms name<input maxLength={200} required value={draft.licenseName} onChange={(event) => setDraft({ ...draft, licenseName: event.target.value })} /></label>
          <label>License or terms link (HTTPS)<input type="url" maxLength={2048} required value={draft.licenseUrl} onChange={(event) => setDraft({ ...draft, licenseUrl: event.target.value })} /></label>
          <label>Permitted use<textarea maxLength={2000} required rows={2} value={draft.permittedUse} onChange={(event) => setDraft({ ...draft, permittedUse: event.target.value })} /></label>
          <label>Attribution text<input maxLength={1000} required value={draft.attribution} onChange={(event) => setDraft({ ...draft, attribution: event.target.value })} /></label>
          <label>Rights class<select value={draft.rightsClass} onChange={(event) => setDraft({ ...draft, rightsClass: event.target.value, contentPolicy: event.target.value === "all_rights_reserved" ? "headline_link" : draft.contentPolicy })}>
            {rightsClasses.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
          <label>Content the system may show<select value={draft.contentPolicy} disabled={draft.rightsClass === "all_rights_reserved"} aria-describedby="policy-reason" onChange={(event) => setDraft({ ...draft, contentPolicy: event.target.value })}>
            {contentPolicies.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
          {draft.rightsClass === "all_rights_reserved" && <p id="policy-reason" className="helper">All rights reserved sources show only the headline, source name, and link.</p>}
          <label>Poll interval in hours (1 to 24; use more than 1 only where the source terms require it)<input type="number" min={1} max={24} step={1} required value={draft.pollIntervalHours} onChange={(event) => setDraft({ ...draft, pollIntervalHours: event.target.value })} /></label>
          <label className="checkbox-label"><input type="checkbox" checked={draft.requireCompleteTitle} onChange={(event) => setDraft({ ...draft, requireCompleteTitle: event.target.checked })} /> Skip items with a truncated title</label>
          <label className="checkbox-label"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} /> Enabled</label>
          <div className="dialog-actions">
            <button type="submit" className="primary-button" disabled={busy}>{busy ? "Saving…" : "Save source"}</button>
            <button type="button" className="secondary-button" onClick={() => { setFormOpen(false); setEditingID(null); }}>Cancel</button>
          </div>
        </form>
      )}
      {sources === null ? <p className="muted">Loading sources…</p> : (
        <div className="admin-table-scroll">
          <table className="admin-table">
            <thead><tr><th scope="col">Source</th><th scope="col">Host</th><th scope="col">Format</th><th scope="col">Status</th><th scope="col">Stories</th><th scope="col">Actions</th></tr></thead>
            <tbody>
              {sources.map((source) => {
                const licensed = hasLicenceRecord(source);
                return (
                  <tr key={source.id}>
                    <th scope="row">{source.name}</th>
                    <td>{sourceHost(source.address)}</td>
                    <td><code>{source.format}</code></td>
                    <td>{source.enabled ? "Enabled" : "Disabled"}</td>
                    <td>{source.storyCount}</td>
                    <td className="admin-actions">
                      <button type="button" className="table-button" disabled={busy}
                        onClick={() => { setDraft(draftFromSource(source)); setEditingID(source.id); setFormOpen(true); }}>Edit</button>
                      <button type="button" className="table-button" disabled={busy || (!source.enabled && !licensed)}
                        onClick={() => void run(() => send(`/api/admin/sources/${encodeURIComponent(source.id)}`, "PATCH", { enabled: !source.enabled }), "Could not update the source.")}>
                        {source.enabled ? "Disable" : "Enable"}
                      </button>
                      {!source.enabled && !licensed && <span className="muted">Add a licence record first.</span>}
                      <button type="button" className="table-button danger-button" disabled={busy || source.storyCount > 0}
                        onClick={() => setPending({
                          kind: "source", id: source.id, name: source.name,
                          consequence: "Collection from this source stops and its record is removed. This can't be undone.",
                        })}>Delete</button>
                      {source.storyCount > 0 && <span className="muted">Has stories: disable instead.</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {pending && <ConfirmDialog pending={pending} busy={busy} onCancel={() => setPending(null)} onConfirm={() => void confirmDelete()} />}
    </section>
  );
}
