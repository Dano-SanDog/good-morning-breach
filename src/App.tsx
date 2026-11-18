import { useCallback, useEffect, useState, type FormEvent } from "react";
import "./styles.css";
import logo from "../logo.svg";

type User = { email: string; role: "admin" | "user" };
type ManagedAccount = {
  id: number;
  email: string;
  role: "admin" | "user";
  enabled: boolean;
  totpRequired: boolean;
  totpEnrolled: boolean;
  createdAt: string;
};
type AdminAuditRecord = {
  id: number;
  actorAccountId: number;
  targetAccountId: number;
  action: string;
  details: string;
  createdAt: string;
};
type AttackTechnique = {
  id: string;
  name: string;
  tactics: string[];
  url: string;
};
type Story = {
  id: number;
  title: string;
  url: string;
  sources: string[];
  attributions: string[];
  publishedAt: string | null;
  categories: string[];
  risk: "Critical" | "High" | "Medium" | "Low" | "Informational";
  sentiment: "Negative" | "Neutral" | "Positive";
  attackTechniques: AttackTechnique[];
};
const riskValues: ReadonlySet<string> = new Set(["Critical", "High", "Medium", "Low", "Informational"]);
const sentimentValues: ReadonlySet<string> = new Set(["Negative", "Neutral", "Positive"]);
type LoginStep = "totp" | "setup";
type View = "loading" | "signin" | LoginStep | "dashboard";

const credentialError = "Email, password, or code is incorrect.";

export function getSafeExternalURL(value: string): URL | null {
  try {
    const url = new URL(value);
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.username === "" &&
      url.password === ""
    ) {
      return url;
    }
  } catch {
    return null;
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseUser(value: unknown): User | null {
  if (
    isRecord(value) &&
    typeof value.email === "string" &&
    (value.role === "admin" || value.role === "user")
  ) {
    return { email: value.email, role: value.role };
  }
  return null;
}

function parseLoginStep(value: unknown): LoginStep | null {
  if (isRecord(value) && (value.next === "setup" || value.next === "totp")) {
    return value.next;
  }
  return null;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item: unknown) => typeof item === "string");
}

function isRisk(value: unknown): value is Story["risk"] {
  return typeof value === "string" && riskValues.has(value);
}

function isSentiment(value: unknown): value is Story["sentiment"] {
  return typeof value === "string" && sentimentValues.has(value);
}

function isAttackTechnique(value: unknown): value is AttackTechnique {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !/^T[0-9]{4}(\.[0-9]{3})?$/.test(value.id) ||
    typeof value.name !== "string" ||
    !isStringArray(value.tactics) ||
    value.tactics.length === 0 ||
    typeof value.url !== "string"
  ) {
    return false;
  }
  const url = getSafeExternalURL(value.url);
  return url !== null &&
    url.protocol === "https:" &&
    url.hostname === "attack.mitre.org" &&
    url.port === "" &&
    url.pathname === `/techniques/${value.id.replace(".", "/")}/` &&
    url.search === "" &&
    url.hash === "";
}

export function parseStories(value: unknown): Story[] | null {
  if (!isRecord(value) || !Array.isArray(value.stories)) {
    return null;
  }
  const stories: Story[] = [];
  for (const item of value.stories) {
    if (
      !isRecord(item) ||
      typeof item.id !== "number" ||
      typeof item.title !== "string" ||
      typeof item.url !== "string" ||
      !isStringArray(item.sources) ||
      !isStringArray(item.attributions) ||
      !isStringArray(item.categories) ||
      !isRisk(item.risk) ||
      !isSentiment(item.sentiment) ||
      !Array.isArray(item.attackTechniques) ||
      !item.attackTechniques.every(isAttackTechnique) ||
      (typeof item.publishedAt !== "string" && item.publishedAt !== null)
    ) {
      return null;
    }
    stories.push({
      id: item.id,
      title: item.title,
      url: item.url,
      sources: item.sources,
      attributions: item.attributions,
      publishedAt: item.publishedAt,
      categories: item.categories,
      risk: item.risk,
      sentiment: item.sentiment,
      attackTechniques: item.attackTechniques,
    });
  }
  return stories;
}

async function responseError(response: Response): Promise<string> {
  try {
    const payload: unknown = await response.json();
    if (isRecord(payload) && typeof payload.error === "string") {
      return payload.error;
    }
  } catch {
    return "The request could not be completed.";
  }
  return "The request could not be completed.";
}

async function mutateJSON(
  path: string,
  method: "POST" | "PATCH" | "DELETE",
  value: Record<string, unknown> = {},
): Promise<Response> {
  return fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-GMB-CSRF": "1",
    },
    body: JSON.stringify(value),
  });
}

function parseManagedAccounts(value: unknown): ManagedAccount[] | null {
  if (!isRecord(value) || !Array.isArray(value.accounts)) {
    return null;
  }
  const accounts: ManagedAccount[] = [];
  for (const item of value.accounts) {
    if (
      !isRecord(item) ||
      typeof item.id !== "number" ||
      typeof item.email !== "string" ||
      (item.role !== "admin" && item.role !== "user") ||
      typeof item.enabled !== "boolean" ||
      typeof item.totpRequired !== "boolean" ||
      typeof item.totpEnrolled !== "boolean" ||
      typeof item.createdAt !== "string"
    ) {
      return null;
    }
    accounts.push({
      id: item.id,
      email: item.email,
      role: item.role,
      enabled: item.enabled,
      totpRequired: item.totpRequired,
      totpEnrolled: item.totpEnrolled,
      createdAt: item.createdAt,
    });
  }
  return accounts;
}

function parseAdminAudit(value: unknown): AdminAuditRecord[] | null {
  if (!isRecord(value) || !Array.isArray(value.events)) {
    return null;
  }
  const records: AdminAuditRecord[] = [];
  for (const item of value.events) {
    if (
      !isRecord(item) ||
      typeof item.id !== "number" ||
      typeof item.actorAccountId !== "number" ||
      typeof item.targetAccountId !== "number" ||
      typeof item.action !== "string" ||
      typeof item.details !== "string" ||
      typeof item.createdAt !== "string"
    ) {
      return null;
    }
    records.push({
      id: item.id,
      actorAccountId: item.actorAccountId,
      targetAccountId: item.targetAccountId,
      action: item.action,
      details: item.details,
      createdAt: item.createdAt,
    });
  }
  return records;
}

export function ExternalStoryLink({ story }: { story: Story }) {
  const url = getSafeExternalURL(story.url);
  if (!url) {
    return <span className="story-title">{story.title}</span>;
  }
  return (
    <div className="story-heading">
      <a className="story-title" href={url.href} target="_blank" rel="noopener noreferrer">
        {story.title}
      </a>
      <span className="story-domain">{url.hostname}</span>
    </div>
  );
}

export function App() {
  const [view, setView] = useState<View>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [stories, setStories] = useState<Story[]>([]);
  const [managedAccounts, setManagedAccounts] = useState<ManagedAccount[]>([]);
  const [adminAudit, setAdminAudit] = useState<AdminAuditRecord[]>([]);
  const [totpSecret, setTotpSecret] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newAccountEmail, setNewAccountEmail] = useState("");
  const [newAccountPassword, setNewAccountPassword] = useState("");
  const [newAccountRole, setNewAccountRole] = useState<"admin" | "user">("user");
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const loadStories = useCallback(async () => {
    const response = await fetch("/api/stories", { credentials: "same-origin" });
    if (!response.ok) {
      throw new Error(await responseError(response));
    }
    const payload: unknown = await response.json();
    const loaded = parseStories(payload);
    if (!loaded) {
      throw new Error("The server returned an invalid stories response.");
    }
    setStories(loaded);
  }, []);

  const loadAdminData = useCallback(async () => {
    const [accountsResponse, auditResponse] = await Promise.all([
      fetch("/api/admin/accounts", { credentials: "same-origin" }),
      fetch("/api/admin/audit", { credentials: "same-origin" }),
    ]);
    if (!accountsResponse.ok) {
      throw new Error(await responseError(accountsResponse));
    }
    if (!auditResponse.ok) {
      throw new Error(await responseError(auditResponse));
    }
    const accounts = parseManagedAccounts(await accountsResponse.json());
    const audit = parseAdminAudit(await auditResponse.json());
    if (!accounts || !audit) {
      throw new Error("The server returned invalid administrator data.");
    }
    setManagedAccounts(accounts);
    setAdminAudit(audit);
  }, []);

  const startSetup = useCallback(async () => {
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/auth/totp/setup/start", "POST");
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      const payload: unknown = await response.json();
      if (!isRecord(payload) || typeof payload.secret !== "string") {
        throw new Error("The server returned an invalid authenticator setup.");
      }
      setTotpSecret(payload.secret);
      setCode("");
      setView("setup");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not start authenticator setup.");
    } finally {
      setBusy(false);
    }
  }, []);

  const enterDashboard = useCallback(
    async (signedInUser: User) => {
      setUser(signedInUser);
      setView("dashboard");
      setMessage("");
      try {
        const requests: Promise<void>[] = [loadStories()];
        if (signedInUser.role === "admin") {
          requests.push(loadAdminData());
        }
        await Promise.all(requests);
      } catch (error) {
        setMessage(error instanceof Error ? error.message : "Could not load dashboard data.");
      }
    },
    [loadAdminData, loadStories],
  );

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        const sessionResponse = await fetch("/api/auth/session", {
          credentials: "same-origin",
        });
        if (sessionResponse.ok) {
          const currentUser = parseUser(await sessionResponse.json());
          if (!currentUser) {
            throw new Error("The server returned an invalid session.");
          }
          if (active) {
            await enterDashboard(currentUser);
          }
          return;
        }
        if (sessionResponse.status !== 401) {
          throw new Error(await responseError(sessionResponse));
        }

        const challengeResponse = await fetch("/api/auth/challenge", {
          credentials: "same-origin",
        });
        if (challengeResponse.ok) {
          const step = parseLoginStep(await challengeResponse.json());
          if (!step) {
            throw new Error("The server returned an invalid sign-in challenge.");
          }
          if (active && step === "setup") {
            await startSetup();
          } else if (active) {
            setView("totp");
          }
          return;
        }
        if (challengeResponse.status !== 401) {
          throw new Error(await responseError(challengeResponse));
        }
        if (active) {
          setView("signin");
        }
      } catch (error) {
        if (active) {
          setView("signin");
          setMessage(error instanceof Error ? error.message : "Could not connect to the server.");
        }
      }
    }
    void initialize();
    return () => {
      active = false;
    };
  }, [enterDashboard, startSetup]);

  useEffect(() => {
    if (view !== "dashboard") {
      return;
    }
    let lastActivitySentAt = 0;
    let active = true;
    const sendActivity = () => {
      const now = Date.now();
      if (now - lastActivitySentAt < 60_000) {
        return;
      }
      lastActivitySentAt = now;
      void mutateJSON("/api/auth/activity", "POST").then((response) => {
        if (active && response.status === 401) {
          setUser(null);
          setView("signin");
          setMessage("Your sign-in expired. Please sign in again.");
        } else if (active && !response.ok) {
          void responseError(response).then(setMessage);
        }
      }).catch(() => {
        if (active) {
          setMessage("Could not refresh your sign-in. Please check the connection.");
        }
      });
    };
    sendActivity();
    window.addEventListener("pointermove", sendActivity);
    window.addEventListener("keydown", sendActivity);
    return () => {
      active = false;
      window.removeEventListener("pointermove", sendActivity);
      window.removeEventListener("keydown", sendActivity);
    };
  }, [view]);

  async function handlePasswordLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/auth/login", "POST", { email, password });
      setPassword("");
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      const payload: unknown = await response.json();
      const signedInUser = parseUser(payload);
      if (signedInUser) {
        setCode("");
        setTotpSecret("");
        await enterDashboard(signedInUser);
        return;
      }
      const step = parseLoginStep(payload);
      if (!step) {
        throw new Error("The server returned an invalid sign-in challenge.");
      }
      if (step === "setup") {
        await startSetup();
      } else {
        setCode("");
        setView("totp");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : credentialError);
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  async function handleTOTP(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const endpoint = view === "setup" ? "/api/auth/totp/setup/confirm" : "/api/auth/totp/login";
    try {
      const response = await mutateJSON(endpoint, "POST", { code });
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      const signedInUser = parseUser(await response.json());
      if (!signedInUser) {
        throw new Error("The server returned an invalid session.");
      }
      setCode("");
      setTotpSecret("");
      await enterDashboard(signedInUser);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : credentialError);
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/auth/logout", "POST");
      if (!response.ok && response.status !== 401) {
        throw new Error(await responseError(response));
      }
      setUser(null);
      setStories([]);
      setManagedAccounts([]);
      setAdminAudit([]);
      setCode("");
      setView("signin");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not sign out.");
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/admin/accounts", "POST", {
        email: newAccountEmail,
        password: newAccountPassword,
        role: newAccountRole,
      });
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      setNewAccountEmail("");
      setNewAccountPassword("");
      await loadAdminData();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not create the account.");
    } finally {
      setNewAccountPassword("");
      setBusy(false);
    }
  }

  async function handleUpdateAccount(
    account: ManagedAccount,
    changes: { role?: "admin" | "user"; enabled?: boolean },
  ) {
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON(`/api/admin/accounts/${account.id}`, "PATCH", changes);
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      await loadAdminData();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not update the account.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteAccount(account: ManagedAccount) {
    if (window.prompt(`Type ${account.email} to confirm account deletion.`) !== account.email) {
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON(`/api/admin/accounts/${account.id}`, "DELETE");
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      await loadAdminData();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not delete the account.");
    } finally {
      setBusy(false);
    }
  }

  if (view === "loading") {
    return <main className="centered-shell"><p>Loading Good Morning Breach…</p></main>;
  }

  if (view === "signin") {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-labelledby="signin-heading">
          <img className="brand-mark" src={logo} alt="" />
          <h1 id="signin-heading">Good Morning Breach</h1>
          <p className="muted">Sign in to your private security briefing.</p>
          <form onSubmit={handlePasswordLogin}>
            <label htmlFor="email">Email address</label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              maxLength={254}
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              maxLength={256}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            {message && <p className="message" role="alert">{message}</p>}
            <button type="submit" className="primary-button" disabled={busy}>
              {busy ? "Signing in…" : "Continue"}
            </button>
          </form>
        </section>
      </main>
    );
  }

  if (view === "totp" || view === "setup") {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-labelledby="totp-heading">
          <img className="brand-mark" src={logo} alt="" />
          <h1 id="totp-heading">{view === "setup" ? "Set up your authenticator" : "Enter your code"}</h1>
          {view === "setup" ? (
            <div className="setup-instructions">
              <p>In your authenticator app, add an account using this key:</p>
              <code className="secret-value">{totpSecret || "Preparing your setup key…"}</code>
              <p className="muted">Enter the six-digit code from the app to finish setup.</p>
            </div>
          ) : (
            <p className="muted">Enter the current six-digit code from your authenticator app.</p>
          )}
          <form onSubmit={handleTOTP}>
            <label htmlFor="totp-code">Authenticator code</label>
            <input
              id="totp-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
            />
            {message && <p className="message" role="alert">{message}</p>}
            <button type="submit" className="primary-button" disabled={busy || (view === "setup" && !totpSecret)}>
              {busy ? "Checking…" : view === "setup" ? "Finish setup" : "Sign in"}
            </button>
          </form>
        </section>
      </main>
    );
  }

  return (
    <div className="dashboard-shell">
      <header className="account-bar">
        <div className="account-brand">
          <img src={logo} alt="" />
          <span>Good Morning Breach</span>
        </div>
        <div className="account-controls">
          <span className="account-email">{user?.email}</span>
          <span className="role-label">{user?.role === "admin" ? "Admin" : "User"}</span>
          <button type="button" className="signout-button" onClick={handleLogout} disabled={busy}>
            Sign out
          </button>
        </div>
      </header>
      <main className="dashboard-content">
        <div className="dashboard-heading">
          <div>
            <h1>This morning</h1>
            <p className="muted">Recent CERT-EU and SANS ISC stories</p>
          </div>
          <span className="story-count">{stories.length} {stories.length === 1 ? "story" : "stories"}</span>
        </div>
        {message && <p className="message" role="alert">{message}</p>}
        {user?.role === "admin" && (
          <section className="admin-panel" aria-labelledby="accounts-heading">
            <div className="dashboard-heading">
              <div>
                <h2 id="accounts-heading">Account management</h2>
                <p className="muted">Create accounts, manage access, and review administrator actions.</p>
              </div>
            </div>
            <form className="account-create-form" onSubmit={handleCreateAccount}>
              <label>
                Email address
                <input
                  type="email"
                  autoComplete="off"
                  maxLength={254}
                  required
                  value={newAccountEmail}
                  onChange={(event) => setNewAccountEmail(event.target.value)}
                />
              </label>
              <label>
                Initial password
                <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={256}
                  required
                  value={newAccountPassword}
                  onChange={(event) => setNewAccountPassword(event.target.value)}
                />
              </label>
              <label>
                Role
                <select
                  value={newAccountRole}
                  onChange={(event) => {
                    if (event.target.value === "admin" || event.target.value === "user") {
                      setNewAccountRole(event.target.value);
                    }
                  }}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
              <button type="submit" className="primary-button" disabled={busy}>
                Create account
              </button>
            </form>
            <div className="admin-table-scroll">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th scope="col">Account</th>
                    <th scope="col">Role</th>
                    <th scope="col">Status</th>
                    <th scope="col">Authenticator</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {managedAccounts.map((account) => {
                    const isCurrentAccount = account.email === user.email;
                    return (
                      <tr key={account.id}>
                        <th scope="row">{account.email}</th>
                        <td>
                          <select
                            aria-label={`Role for ${account.email}`}
                            value={account.role}
                            disabled={busy || isCurrentAccount}
                            onChange={(event) => {
                              if (event.target.value === "admin" || event.target.value === "user") {
                                void handleUpdateAccount(account, { role: event.target.value });
                              }
                            }}
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>
                        <td>{account.enabled ? "Enabled" : "Disabled"}</td>
                        <td>
                          {!account.totpRequired
                            ? "Not required"
                            : account.totpEnrolled
                              ? "Enrolled"
                              : "Required"}
                        </td>
                        <td className="admin-actions">
                          <button
                            type="button"
                            className="table-button"
                            disabled={busy || isCurrentAccount}
                            onClick={() => void handleUpdateAccount(account, { enabled: !account.enabled })}
                          >
                            {account.enabled ? "Disable" : "Enable"}
                          </button>
                          <button
                            type="button"
                            className="table-button danger-button"
                            disabled={busy || isCurrentAccount}
                            onClick={() => void handleDeleteAccount(account)}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <h3 className="audit-heading">Administrator action log</h3>
            {adminAudit.length === 0 ? (
              <p className="muted">No administrator actions recorded yet.</p>
            ) : (
              <ol className="audit-list">
                {adminAudit.map((record) => (
                  <li key={record.id}>
                    <strong>{record.action.replaceAll("_", " ")}</strong>
                    <span>Actor #{record.actorAccountId}, target #{record.targetAccountId}</span>
                    <time dateTime={record.createdAt}>{new Date(record.createdAt).toLocaleString()}</time>
                    <code>{record.details}</code>
                  </li>
                ))}
              </ol>
            )}
          </section>
        )}
        {stories.length === 0 ? (
          <section className="empty-state" aria-live="polite">
            <h2>No recent stories</h2>
            <p>Run the collection command to check for new stories.</p>
          </section>
        ) : (
          <ol className="story-ledger">
            {stories.map((story) => (
              <li className={`story-row risk-${story.risk.toLowerCase()}`} key={story.id}>
                <span className="story-spine" aria-hidden="true" />
                <div className="story-content">
                  <ExternalStoryLink story={story} />
                  <div className="story-analysis">
                    <span className={`risk-chip risk-${story.risk.toLowerCase()}`}>Risk: {story.risk}</span>
                    <span className="sentiment-label">Tone: {story.sentiment}</span>
                    {story.categories.map((category) => (
                      <span className="tag-chip" key={category}>{category}</span>
                    ))}
                    {story.attackTechniques.map((technique) => (
                      <a className="tag-chip attack-chip" href={technique.url} key={technique.id} target="_blank" rel="noopener noreferrer">
                        <span className="attack-id">{technique.id}</span>: {technique.name} ({technique.tactics.join(", ")})
                      </a>
                    ))}
                  </div>
                  <dl className="story-metadata">
                    <div>
                      <dt>Source</dt>
                      <dd>{story.sources.join(", ")}</dd>
                    </div>
                    <div>
                      <dt>Published</dt>
                      <dd>
                        {story.publishedAt
                          ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(story.publishedAt))
                          : "Time unavailable"}
                      </dd>
                    </div>
                  </dl>
                  {story.attributions.length > 0 && (
                    <div className="story-attributions">
                      {story.attributions.map((attribution) => (
                        <p key={attribution}>{attribution}</p>
                      ))}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </main>
    </div>
  );
}
