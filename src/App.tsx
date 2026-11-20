import { useCallback, useEffect, useState, type FormEvent } from "react";
import "./styles.css";
import logo from "../logo.svg";
import { CatalogAdmin } from "./CatalogAdmin";

type User = { email: string; role: "admin" | "user" };
type ManagedAccount = {
  id: number;
  email: string;
  role: "admin" | "user";
  enabled: boolean;
  createdAt: string;
};
type AdminAuditRecord = {
  id: number;
  actorAccountId: number;
  targetAccountId: number | null;
  targetKind: string;
  targetId: string;
  action: string;
  details: string;
  createdAt: string;
};
type SourceStatus = {
  id: string;
  name: string;
  enabled: boolean;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastFailureCause: string | null;
  failingSince: string | null;
  warning: boolean;
};
type StoryFilters = {
  search: string;
  category: string;
  risk: string;
  source: string;
  attack: string;
  start: string;
  end: string;
};
type AlertSettings = {
  enabled: boolean;
  time: string;
  timeZone: string;
  days: number[];
  minimumRisk: string;
};
const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const emptyFilters: StoryFilters = { search: "", category: "", risk: "", source: "", attack: "", start: "", end: "" };
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
  cves: string[];
  related: RelatedStory[];
};
type RelatedStory = { id: number; title: string; url: string; cve: string };
const cvePattern = /^CVE-[0-9]{4}-[0-9]{4,19}$/;
const riskValues: ReadonlySet<string> = new Set(["Critical", "High", "Medium", "Low", "Informational"]);
const sentimentValues: ReadonlySet<string> = new Set(["Negative", "Neutral", "Positive"]);
type View = "loading" | "signin" | "forgot" | "dashboard";

const credentialError = "Email or password is incorrect.";

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

export function parseResetToken(hash: string): string {
  return /^#reset=([A-Za-z0-9]{1,128})$/.exec(hash)?.[1] ?? "";
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

function isRelatedStory(value: unknown): value is RelatedStory {
  return (
    isRecord(value) &&
    typeof value.id === "number" &&
    typeof value.title === "string" &&
    typeof value.url === "string" &&
    typeof value.cve === "string" &&
    cvePattern.test(value.cve)
  );
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
      !isStringArray(item.cves) ||
      !item.cves.every((cve) => cvePattern.test(cve)) ||
      !Array.isArray(item.related) ||
      !item.related.every(isRelatedStory) ||
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
      cves: item.cves,
      related: item.related,
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
  method: "POST" | "PUT" | "PATCH" | "DELETE",
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
      typeof item.createdAt !== "string"
    ) {
      return null;
    }
    accounts.push({
      id: item.id,
      email: item.email,
      role: item.role,
      enabled: item.enabled,
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
      (item.targetAccountId !== null && typeof item.targetAccountId !== "number") ||
      (item.targetKind !== undefined && typeof item.targetKind !== "string") ||
      (item.targetId !== undefined && typeof item.targetId !== "string") ||
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
      targetKind: typeof item.targetKind === "string" ? item.targetKind : "",
      targetId: typeof item.targetId === "string" ? item.targetId : "",
      action: item.action,
      details: item.details,
      createdAt: item.createdAt,
    });
  }
  return records;
}

export type ChannelView = {
  emailEnabled: boolean; slackEnabled: boolean; smsEnabled: boolean;
  slackWebhookSaved: boolean; smsAvailable: boolean;
  phoneMasked: string; phoneVerified: boolean; pendingPhoneMasked: string;
};

export function parseChannelView(value: unknown): ChannelView | null {
  if (!isRecord(value)) return null;
  const flags = ["emailEnabled", "slackEnabled", "smsEnabled", "slackWebhookSaved", "smsAvailable", "phoneVerified"] as const;
  for (const flag of flags) if (typeof value[flag] !== "boolean") return null;
  if (typeof value.phoneMasked !== "string" || typeof value.pendingPhoneMasked !== "string") return null;
  return {
    emailEnabled: value.emailEnabled as boolean, slackEnabled: value.slackEnabled as boolean,
    smsEnabled: value.smsEnabled as boolean, slackWebhookSaved: value.slackWebhookSaved as boolean,
    smsAvailable: value.smsAvailable as boolean, phoneMasked: value.phoneMasked,
    phoneVerified: value.phoneVerified as boolean, pendingPhoneMasked: value.pendingPhoneMasked,
  };
}

export function parseAlertSettings(value: unknown): AlertSettings | null {
  if (!isRecord(value) || typeof value.enabled !== "boolean" ||
      typeof value.time !== "string" || !/^\d{2}:\d{2}$/.test(value.time) ||
      typeof value.timeZone !== "string" || !Array.isArray(value.days) ||
      value.days.length < 1 || value.days.length > 7 ||
      !value.days.every((day: unknown) => typeof day === "number" && Number.isInteger(day) && day >= 0 && day <= 6) ||
      new Set(value.days).size !== value.days.length ||
      typeof value.minimumRisk !== "string" || !riskValues.has(value.minimumRisk)) return null;
  return {
    enabled: value.enabled, time: value.time, timeZone: value.timeZone,
    days: value.days, minimumRisk: value.minimumRisk,
  };
}

function nullableTimestamp(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
}

export function parseSourceStatuses(value: unknown): SourceStatus[] | null {
  if (!isRecord(value) || !Array.isArray(value.sources)) return null;
  const statuses: SourceStatus[] = [];
  for (const item of value.sources) {
    if (!isRecord(item) || typeof item.id !== "string" || typeof item.name !== "string" ||
        typeof item.enabled !== "boolean" || !nullableTimestamp(item.lastSuccessAt) ||
        !nullableTimestamp(item.lastFailureAt) || !nullableTimestamp(item.failingSince) ||
        (item.lastFailureCause !== null && typeof item.lastFailureCause !== "string") ||
        typeof item.warning !== "boolean") return null;
    statuses.push({
      id: item.id, name: item.name, enabled: item.enabled, lastSuccessAt: item.lastSuccessAt,
      lastFailureAt: item.lastFailureAt, lastFailureCause: item.lastFailureCause,
      failingSince: item.failingSince, warning: item.warning,
    });
  }
  return statuses;
}

export function storyFilterQuery(filters: StoryFilters, offset: number): string {
  const params = new URLSearchParams();
  for (const key of ["search", "category", "risk", "source", "attack"] as const) {
    if (filters[key].trim()) params.set(key, filters[key].trim());
  }
  if (filters.start || filters.end) {
    if (!filters.start || !filters.end) throw new Error("Choose both a start and end date.");
    const start = new Date(`${filters.start}T00:00:00`);
    const end = new Date(`${filters.end}T00:00:00`);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end < start) {
      throw new Error("Choose a valid date range.");
    }
    end.setDate(end.getDate() + 1);
    params.set("after", start.toISOString());
    params.set("before", end.toISOString());
  }
  if (offset > 0) params.set("offset", String(offset));
  const query = params.toString();
  return query ? `?${query}` : "";
}

function formatStatusTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Never";
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
  const [alertSettings, setAlertSettings] = useState<AlertSettings | null>(null);
  const [alertSaved, setAlertSaved] = useState(false);
  const [channels, setChannels] = useState<ChannelView | null>(null);
  const [webhookInput, setWebhookInput] = useState("");
  const [replacingWebhook, setReplacingWebhook] = useState(false);
  const [phoneInput, setPhoneInput] = useState("");
  const [codeInput, setCodeInput] = useState("");
  const [channelNotice, setChannelNotice] = useState("");
  const [channelError, setChannelError] = useState("");
  const [channelBusy, setChannelBusy] = useState("");
  const [sourceStatuses, setSourceStatuses] = useState<SourceStatus[] | null>(null);
  const [filterDraft, setFilterDraft] = useState<StoryFilters>(emptyFilters);
  const [appliedFilters, setAppliedFilters] = useState<StoryFilters>(emptyFilters);
  const [storyOffset, setStoryOffset] = useState(0);
  const [hasMoreStories, setHasMoreStories] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newAccountEmail, setNewAccountEmail] = useState("");
  const [newAccountPassword, setNewAccountPassword] = useState("");
  const [newAccountRole, setNewAccountRole] = useState<"admin" | "user">("user");
  const [message, setMessage] = useState("");
  const [resetToken, setResetToken] = useState(() =>
    typeof window === "undefined" ? "" : parseResetToken(window.location.hash),
  );
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const loadStories = useCallback(async (filters: StoryFilters, offset: number) => {
    const response = await fetch(`/api/stories${storyFilterQuery(filters, offset)}`, { credentials: "same-origin" });
    if (!response.ok) {
      throw new Error(await responseError(response));
    }
    const payload: unknown = await response.json();
    const loaded = parseStories(payload);
    if (!loaded || !isRecord(payload) || typeof payload.hasMore !== "boolean") {
      throw new Error("The server returned an invalid stories response.");
    }
    setStories(loaded);
    setHasMoreStories(payload.hasMore);
    setStoryOffset(offset);
    setAppliedFilters(filters);
  }, []);

  const loadSourceStatuses = useCallback(async () => {
    const response = await fetch("/api/admin/sources", { credentials: "same-origin" });
    if (!response.ok) throw new Error(await responseError(response));
    const statuses = parseSourceStatuses(await response.json());
    if (!statuses) throw new Error("The server returned invalid source health data.");
    setSourceStatuses(statuses);
  }, []);

  const loadChannels = useCallback(async () => {
    const response = await fetch("/api/alert-channels", { credentials: "same-origin" });
    if (!response.ok) throw new Error(await responseError(response));
    const view = parseChannelView(await response.json());
    if (!view) throw new Error("The server returned invalid channel settings.");
    setChannels(view);
  }, []);

  const loadAlertSettings = useCallback(async () => {
    const response = await fetch("/api/alert-settings", { credentials: "same-origin" });
    if (!response.ok) throw new Error(await responseError(response));
    const settings = parseAlertSettings(await response.json());
    if (!settings) throw new Error("The server returned invalid alert settings.");
    setAlertSettings({ ...settings, timeZone: settings.timeZone || Intl.DateTimeFormat().resolvedOptions().timeZone || "" });
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

  const enterDashboard = useCallback(
    async (signedInUser: User) => {
      setUser(signedInUser);
      setView("dashboard");
      setMessage("");
      try {
        setFilterDraft(emptyFilters);
        const requests: Promise<void>[] = [loadStories(emptyFilters, 0), loadAlertSettings(), loadChannels()];
        if (signedInUser.role === "admin") {
          requests.push(loadAdminData(), loadSourceStatuses());
        }
        await Promise.all(requests);
      } catch (error) {
        setMessage(error instanceof Error ? error.message : "Could not load dashboard data.");
      }
    },
    [loadAdminData, loadAlertSettings, loadChannels, loadSourceStatuses, loadStories],
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
  }, [enterDashboard]);

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
      if (!signedInUser) {
        throw new Error("The server returned an invalid session.");
      }
      await enterDashboard(signedInUser);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : credentialError);
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  async function handleForgot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/auth/password-reset/request", "POST", { email });
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      setNotice("If that address has an account, we sent a link.");
      setView("signin");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The request could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleResetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const response = await mutateJSON("/api/auth/password-reset/confirm", "POST", {
        token: resetToken,
        password,
      });
      if (!response.ok) {
        throw new Error(await responseError(response));
      }
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      setResetToken("");
      setNotice("Password changed. Sign in with your new password.");
      setUser(null);
      setView("signin");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The request could not be completed.");
    } finally {
      setPassword("");
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
      setSourceStatuses(null);
      setAlertSettings(null);
      setAlertSaved(false);
      setChannels(null);
      setWebhookInput(""); setPhoneInput(""); setCodeInput("");
      setView("signin");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not sign out.");
    } finally {
      setBusy(false);
    }
  }

  async function channelAction(label: string, run: () => Promise<string>) {
    setChannelBusy(label);
    setChannelError("");
    setChannelNotice("");
    try {
      setChannelNotice(await run());
      await loadChannels();
    } catch (error) {
      setChannelError(error instanceof Error ? error.message : "Could not update delivery channels.");
    } finally {
      setChannelBusy("");
    }
  }

  async function postChannel(path: string, method: "PUT" | "POST", body: Record<string, unknown>) {
    const response = await mutateJSON(path, method, body);
    if (!response.ok) throw new Error(await responseError(response));
    return response;
  }

  function saveChannelFlags(next: Partial<Pick<ChannelView, "emailEnabled" | "slackEnabled" | "smsEnabled">>) {
    if (!channels) return;
    const merged = { ...channels, ...next };
    void channelAction("Saving…", async () => {
      await postChannel("/api/alert-channels", "PUT", {
        emailEnabled: merged.emailEnabled, slackEnabled: merged.slackEnabled, smsEnabled: merged.smsEnabled,
      });
      return "Delivery channels saved.";
    });
  }

  function handleSaveWebhook(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const webhook = webhookInput;
    void channelAction("Sending test…", async () => {
      const response = await postChannel("/api/alert-channels/slack", "POST", { webhook });
      const result: unknown = await response.json();
      setWebhookInput("");
      setReplacingWebhook(false);
      return isRecord(result) && result.testFailed === true
        ? "Slack webhook saved, but the test message failed. Check the webhook and try again."
        : "Slack webhook saved. A test message was sent.";
    });
  }

  function handleSendCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const phone = phoneInput;
    void channelAction("Sending code…", async () => {
      await postChannel("/api/alert-channels/phone", "POST", { phone });
      setPhoneInput("");
      return "We sent a 6-digit code. It expires in 10 minutes.";
    });
  }

  function handleVerifyCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = codeInput;
    void channelAction("Verifying…", async () => {
      await postChannel("/api/alert-channels/phone/verify", "POST", { code });
      setCodeInput("");
      return "Phone number verified. Text message alerts are on.";
    });
  }

  async function handleSaveAlertSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!alertSettings) return;
    setBusy(true);
    setMessage("");
    setAlertSaved(false);
    try {
      const response = await mutateJSON("/api/alert-settings", "PUT", alertSettings);
      if (!response.ok) throw new Error(await responseError(response));
      setAlertSaved(true);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not save alert settings.");
    } finally {
      setBusy(false);
    }
  }

  async function applyStoryFilters(filters: StoryFilters, offset: number) {
    setBusy(true);
    setMessage("");
    try {
      await loadStories(filters, offset);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not load stories.");
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

  if (resetToken !== "") {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-labelledby="reset-heading">
          <img className="brand-mark" src={logo} alt="" />
          <h1 id="reset-heading">Choose a new password</h1>
          <p className="muted">Use at least 12 characters.</p>
          <form onSubmit={handleResetPassword}>
            <label htmlFor="new-password">New password</label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={256}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            {message && <p className="message" role="alert">{message}</p>}
            <button type="submit" className="primary-button" disabled={busy}>
              {busy ? "Saving…" : "Change password"}
            </button>
          </form>
        </section>
      </main>
    );
  }

  if (view === "forgot") {
    return (
      <main className="auth-shell">
        <section className="auth-panel" aria-labelledby="forgot-heading">
          <img className="brand-mark" src={logo} alt="" />
          <h1 id="forgot-heading">Reset your password</h1>
          <p className="muted">We will email a link that works for 30 minutes.</p>
          <form onSubmit={handleForgot}>
            <label htmlFor="reset-email">Email address</label>
            <input
              id="reset-email"
              type="email"
              autoComplete="username"
              maxLength={254}
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            {message && <p className="message" role="alert">{message}</p>}
            <button type="submit" className="primary-button" disabled={busy}>
              {busy ? "Sending…" : "Send reset link"}
            </button>
            <button type="button" className="secondary-button" onClick={() => { setMessage(""); setView("signin"); }}>
              Back to sign in
            </button>
          </form>
        </section>
      </main>
    );
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
            {notice && <p className="muted" role="status">{notice}</p>}
            {message && <p className="message" role="alert">{message}</p>}
            <button type="submit" className="primary-button" disabled={busy}>
              {busy ? "Signing in…" : "Continue"}
            </button>
            <button type="button" className="secondary-button" onClick={() => { setMessage(""); setNotice(""); setView("forgot"); }}>
              Forgot password?
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
            <p className="muted">Stories from your enabled sources</p>
          </div>
          <span className="story-count">{stories.length} {stories.length === 1 ? "story" : "stories"} on this page</span>
        </div>
        {message && <p className="message" role="alert">{message}</p>}
        <details className="alert-settings">
          <summary>Alert preferences</summary>
          <p>Choose when your morning alert is sent and where it is delivered.</p>
          {alertSettings === null ? <p className="muted">Alert settings are unavailable.</p> : (
            <form onSubmit={handleSaveAlertSettings}>
              <label className="alert-toggle"><input type="checkbox" checked={alertSettings.enabled} onChange={(event) => {
                setAlertSaved(false); setAlertSettings({ ...alertSettings, enabled: event.target.checked });
              }} /> Send my morning alert</label>
              <div className="alert-settings-fields">
                <label>Time<input type="time" required value={alertSettings.time} onChange={(event) => {
                  setAlertSaved(false); setAlertSettings({ ...alertSettings, time: event.target.value });
                }} /></label>
                <label>Time zone<input required maxLength={100} value={alertSettings.timeZone} onChange={(event) => {
                  setAlertSaved(false); setAlertSettings({ ...alertSettings, timeZone: event.target.value });
                }} /><small>Use an IANA time zone, such as America/Los_Angeles.</small></label>
                <label>Minimum risk<select value={alertSettings.minimumRisk} onChange={(event) => {
                  setAlertSaved(false); setAlertSettings({ ...alertSettings, minimumRisk: event.target.value });
                }}>{Array.from(riskValues).map((risk) => <option key={risk} value={risk}>{risk}</option>)}</select></label>
              </div>
              <fieldset>
                <legend>Days</legend>
                <div className="alert-days">
                  {weekdays.map((day, index) => <label key={day}>
                    <input type="checkbox" checked={alertSettings.days.includes(index)} onChange={(event) => {
                      const days = event.target.checked
                        ? [...alertSettings.days, index].sort((a, b) => a - b)
                        : alertSettings.days.filter((value) => value !== index);
                      setAlertSaved(false); setAlertSettings({ ...alertSettings, days });
                    }} /> {day}
                  </label>)}
                </div>
              </fieldset>
              {alertSettings.days.length === 0 && <p className="message" role="alert">Select at least one day.</p>}
              <button type="submit" className="primary-button" disabled={busy || alertSettings.days.length === 0}>Save preferences</button>
              {alertSaved && <p role="status">Preferences saved.</p>}
            </form>
          )}
          {channels && (
            <section className="alert-channels" aria-label="Delivery channels">
              <h3>Delivery channels</h3>
              <label className="alert-toggle"><input type="checkbox" checked={channels.emailEnabled} disabled={channelBusy !== ""}
                onChange={(event) => saveChannelFlags({ emailEnabled: event.target.checked })} /> Email</label>
              <label className="alert-toggle"><input type="checkbox" checked={channels.slackEnabled}
                disabled={channelBusy !== "" || !channels.slackWebhookSaved}
                onChange={(event) => saveChannelFlags({ slackEnabled: event.target.checked })} /> Slack</label>
              {!channels.slackWebhookSaved && <p className="muted">Save a Slack webhook below to turn on Slack.</p>}
              <label className="alert-toggle"><input type="checkbox" checked={channels.smsEnabled}
                disabled={channelBusy !== "" || !channels.phoneVerified || !channels.smsAvailable}
                onChange={(event) => saveChannelFlags({ smsEnabled: event.target.checked })} /> Text message</label>
              {!channels.smsAvailable && <p className="muted">Text messages are not set up on this server.</p>}
              {channels.smsAvailable && !channels.phoneVerified && <p className="muted">Verify a phone number below to turn on text messages.</p>}

              {channels.slackWebhookSaved && !replacingWebhook ? (
                <p>Slack webhook saved. <button type="button" className="secondary-button" onClick={() => setReplacingWebhook(true)}>Replace</button></p>
              ) : (
                <form onSubmit={handleSaveWebhook}>
                  <label>Slack incoming webhook address
                    <input type="password" autoComplete="off" required maxLength={300} value={webhookInput}
                      onChange={(event) => setWebhookInput(event.target.value)} />
                  </label>
                  <button type="submit" className="primary-button" disabled={channelBusy !== ""}>{channelBusy === "Sending test…" ? "Sending test…" : "Save and send test"}</button>
                </form>
              )}

              {channels.smsAvailable && (
                <>
                  {channels.phoneVerified && <p>Verified number: <span className="identifier">{channels.phoneMasked}</span></p>}
                  <form onSubmit={handleSendCode}>
                    <label>Phone number (with country code, such as +15551234567)
                      <input type="tel" autoComplete="tel" required maxLength={16} value={phoneInput}
                        onChange={(event) => setPhoneInput(event.target.value)} />
                    </label>
                    <button type="submit" className="secondary-button" disabled={channelBusy !== ""}>{channelBusy === "Sending code…" ? "Sending code…" : "Verify number"}</button>
                  </form>
                  {channels.pendingPhoneMasked && (
                    <form onSubmit={handleVerifyCode}>
                      <label>Code sent to <span className="identifier">{channels.pendingPhoneMasked}</span>
                        <input inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" maxLength={6} value={codeInput}
                          onChange={(event) => setCodeInput(event.target.value)} />
                      </label>
                      <button type="submit" className="primary-button" disabled={channelBusy !== ""}>{channelBusy === "Verifying…" ? "Verifying…" : "Confirm code"}</button>
                    </form>
                  )}
                  <p className="muted">Reply STOP to a text message to opt out. Standard message rates may apply.</p>
                </>
              )}
              {channelNotice && <p role="status">{channelNotice}</p>}
              {channelError && <p className="message" role="alert">Error: {channelError}</p>}
            </section>
          )}
        </details>
        <details className="story-filters">
          <summary>Filter stories</summary>
          <form onSubmit={(event) => { event.preventDefault(); void applyStoryFilters(filterDraft, 0); }}>
            <label>Search titles<input type="search" maxLength={200} value={filterDraft.search} onChange={(event) => setFilterDraft({ ...filterDraft, search: event.target.value })} /></label>
            <label>Category<input maxLength={200} placeholder="Exact category name" value={filterDraft.category} onChange={(event) => setFilterDraft({ ...filterDraft, category: event.target.value })} /></label>
            <label>Risk<select value={filterDraft.risk} onChange={(event) => setFilterDraft({ ...filterDraft, risk: event.target.value })}>
              <option value="">All risks</option>
              {Array.from(riskValues).map((risk) => <option key={risk} value={risk}>{risk}</option>)}
            </select></label>
            <label>Source<input maxLength={200} placeholder="Exact source name" value={filterDraft.source} onChange={(event) => setFilterDraft({ ...filterDraft, source: event.target.value })} /></label>
            <label>ATT&amp;CK tactic or technique<input maxLength={200} placeholder="Name or ID, e.g. T1190" value={filterDraft.attack} onChange={(event) => setFilterDraft({ ...filterDraft, attack: event.target.value })} /></label>
            <label>From date<input type="date" value={filterDraft.start} onChange={(event) => setFilterDraft({ ...filterDraft, start: event.target.value })} /></label>
            <label>Through date<input type="date" value={filterDraft.end} onChange={(event) => setFilterDraft({ ...filterDraft, end: event.target.value })} /></label>
            <button type="submit" className="primary-button" disabled={busy}>Apply filters</button>
          </form>
        </details>
        {Object.values(appliedFilters).some(Boolean) && (
          <div className="active-filters" aria-label="Active filters">
            {(["search", "category", "risk", "source", "attack"] as const).filter((key) => appliedFilters[key]).map((key) => (
              <button type="button" className="filter-chip" key={key} disabled={busy} onClick={() => {
                const next = { ...appliedFilters, [key]: "" };
                setFilterDraft(next);
                void applyStoryFilters(next, 0);
              }}>Remove {key}: {appliedFilters[key]} ×</button>
            ))}
            {appliedFilters.start && <button type="button" className="filter-chip" disabled={busy} onClick={() => {
              const next = { ...appliedFilters, start: "", end: "" };
              setFilterDraft(next);
              void applyStoryFilters(next, 0);
            }}>Remove dates: {appliedFilters.start}–{appliedFilters.end} ×</button>}
          </div>
        )}
        {stories.length === 0 ? (
          <section className="empty-state" aria-live="polite">
            <h2>No matching stories</h2>
            <p>Change the filters or check for new stories.</p>
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
                    {story.cves.map((cve) => (
                      <span className="tag-chip attack-id" key={cve}>{cve}</span>
                    ))}
                  </div>
                  {story.related.length > 0 && (
                    <details className="story-related">
                      <summary>Related: {story.related[0]?.cve}</summary>
                      <ul>
                        {story.related.map((related) => {
                          const relatedUrl = getSafeExternalURL(related.url);
                          return (
                            <li key={related.id}>
                              {relatedUrl ? (
                                <a href={relatedUrl.href} target="_blank" rel="noopener noreferrer">{related.title}</a>
                              ) : (
                                related.title
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    </details>
                  )}
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
        {(storyOffset > 0 || hasMoreStories) && <nav className="story-pagination" aria-label="Story pages">
          <button type="button" className="table-button" disabled={busy || storyOffset === 0} onClick={() => void applyStoryFilters(appliedFilters, Math.max(0, storyOffset - 100))}>Previous</button>
          <span>Page {Math.floor(storyOffset / 100) + 1}</span>
          <button type="button" className="table-button" disabled={busy || !hasMoreStories} onClick={() => void applyStoryFilters(appliedFilters, storyOffset + 100)}>Next</button>
        </nav>}
        {user?.role === "admin" && (
          <section className="source-health" aria-labelledby="source-health-heading">
            <h2 id="source-health-heading">Source health</h2>
            {sourceStatuses?.filter((source) => source.warning).map((source) => (
              <p className="source-warning" role="alert" key={source.id}>
                <strong>Warning: {source.name}</strong> has had no successful collection since failures began{" "}
                {source.failingSince ? `${Math.floor((Date.now() - Date.parse(source.failingSince)) / 3_600_000)} hours ago` : "at least 24 hours ago"}.
              </p>
            ))}
            <details>
              <summary>View source collection status</summary>
              {sourceStatuses === null ? <p className="muted">Source health is not available.</p> : sourceStatuses.length === 0 ? <p className="muted">No sources available.</p> : (
                <div className="admin-table-scroll">
                  <table className="admin-table">
                    <thead><tr><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Last success</th><th scope="col">Last failure</th><th scope="col">Failure cause</th></tr></thead>
                    <tbody>
                      {sourceStatuses.map((source) => (
                        <tr key={source.id}>
                          <th scope="row">{source.name}</th>
                          <td>{source.enabled ? "Enabled" : "Disabled"}</td>
                          <td>{formatStatusTime(source.lastSuccessAt)}</td>
                          <td>{formatStatusTime(source.lastFailureAt)}</td>
                          <td>{source.lastFailureCause || "None"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </details>
          </section>
        )}
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
                    <span>Actor #{record.actorAccountId}, target {record.targetKind && record.targetId ? `${record.targetKind} ${record.targetId}` : `#${record.targetAccountId ?? "none"}`}</span>
                    <time dateTime={record.createdAt}>{new Date(record.createdAt).toLocaleString()}</time>
                    <code>{record.details}</code>
                  </li>
                ))}
              </ol>
            )}
          </section>
        )}
        {user?.role === "admin" && <CatalogAdmin onChanged={() => void loadSourceStatuses().catch(() => undefined)} />}
      </main>
      <DashboardNotices />
    </div>
  );
}

export function DashboardNotices() {
  return (
    <footer className="dashboard-notices" aria-label="Required notices">
      <p>This product uses the NVD API but is not endorsed or certified by the NVD.</p>
      <p>
        © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.{" "}
        <a href="https://attack.mitre.org/resources/legal-and-branding/terms-of-use/" rel="noopener noreferrer">ATT&amp;CK terms of use</a>
      </p>
      <p>
        MITRE ATT&amp;CK® and ATT&amp;CK® are registered trademarks of The MITRE Corporation.
      </p>
      <p>
        Breach data from <a href="https://haveibeenpwned.com" rel="noopener noreferrer">Have I Been Pwned</a> (CC BY 4.0).
      </p>
    </footer>
  );
}
