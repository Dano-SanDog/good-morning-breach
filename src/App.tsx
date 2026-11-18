import { useCallback, useEffect, useState, type FormEvent } from "react";
import "./styles.css";
import logo from "../logo.svg";

type User = { email: string; role: "admin" | "user" };
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

async function postJSON(path: string, value: Record<string, string>): Promise<Response> {
  return fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-GMB-CSRF": "1",
    },
    body: JSON.stringify(value),
  });
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
  const [totpSecret, setTotpSecret] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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

  const startSetup = useCallback(async () => {
    setBusy(true);
    setMessage("");
    try {
      const response = await postJSON("/api/auth/totp/setup/start", {});
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
        await loadStories();
      } catch (error) {
        setMessage(error instanceof Error ? error.message : "Could not load stories.");
      }
    },
    [loadStories],
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
      void postJSON("/api/auth/activity", {}).then((response) => {
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
      const response = await postJSON("/api/auth/login", { email, password });
      setPassword("");
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      const step = parseLoginStep(await response.json());
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
      const response = await postJSON(endpoint, { code });
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
      const response = await postJSON("/api/auth/logout", {});
      if (!response.ok && response.status !== 401) {
        throw new Error(await responseError(response));
      }
      setUser(null);
      setStories([]);
      setCode("");
      setView("signin");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not sign out.");
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
