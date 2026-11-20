import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import { App, DashboardNotices, ExternalStoryLink, getSafeExternalURL, parseAlertSettings, parseResetToken, parseSourceStatuses, parseStories, storyFilterQuery } from "./App";

test("renders the application title", () => {
  const markup = renderToStaticMarkup(createElement(App));
  expect(markup).toContain("Good Morning Breach");
});

test("renders story titles as text and rejects unsafe external links", () => {
  const markup = renderToStaticMarkup(
    createElement(ExternalStoryLink, {
      story: {
        id: 1,
        title: "<b>untrusted</b>",
        url: "javascript:alert(1)",
        sources: ["CERT-EU"],
        attributions: ["Source: CERT-EU"],
        publishedAt: null,
        categories: ["Other"],
        risk: "Informational",
        sentiment: "Neutral",
        attackTechniques: [],
      },
    }),
  );
  expect(markup).toContain("&lt;b&gt;untrusted&lt;/b&gt;");
  expect(markup).not.toContain("<a ");
  expect(getSafeExternalURL("https://example.org/advisory")?.hostname).toBe("example.org");
  expect(getSafeExternalURL("https://trusted.example@evil.example/")).toBeNull();
});

test("parses analysis labels as plain text and rejects invalid score values", () => {
  const parsed = parseStories({
    stories: [{
      id: 1,
      title: "<b>untrusted</b>",
      url: "https://example.org/advisory",
      sources: ["CERT-EU"],
      attributions: ["Source: CERT-EU"],
      publishedAt: null,
      categories: ["__proto__"],
      risk: "High",
      sentiment: "Negative",
      attackTechniques: [{
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactics: ["Initial Access"],
        url: "https://attack.mitre.org/techniques/T1190/",
      }],
    }],
  });

  expect(parsed?.[0]?.categories).toEqual(["__proto__"]);
  expect(parsed?.[0]?.risk).toBe("High");
  expect(parsed?.[0]?.sentiment).toBe("Negative");
  expect(parsed?.[0]?.attributions).toEqual(["Source: CERT-EU"]);
  expect(parsed?.[0]?.attackTechniques[0]?.url).toBe("https://attack.mitre.org/techniques/T1190/");
  expect(Object.prototype).not.toHaveProperty("polluted");

  expect(parseStories({
    stories: [{
      id: 1,
      title: "Headline",
      url: "https://example.org/advisory",
      sources: ["CERT-EU"],
      attributions: ["Source: CERT-EU"],
      publishedAt: null,
      categories: ["Other"],
      risk: "Severe",
      sentiment: "Neutral",
      attackTechniques: [],
    }],
  })).toBeNull();

  expect(parseStories({
    stories: [{
      id: 1,
      title: "Headline",
      url: "https://example.org/advisory",
      sources: ["CERT-EU"],
      attributions: ["Source: CERT-EU"],
      publishedAt: null,
      categories: ["Other"],
      risk: "High",
      sentiment: "Negative",
      attackTechniques: [{
        id: `T1190"><script`,
        name: "Invalid",
        tactics: ["Initial Access"],
        url: "https://evil.example/techniques/T1190/",
      }],
    }],
  })).toBeNull();
});

test("validates source health data before displaying it", () => {
  const status = {
    id: "feed", name: "<feed>", enabled: true, lastSuccessAt: null,
    lastFailureAt: "2026-01-01T00:00:00Z", lastFailureCause: "failed",
    failingSince: "2026-01-01T00:00:00Z", warning: true,
  };
  expect(parseSourceStatuses({ sources: [status] })?.[0]?.warning).toBe(true);
  expect(parseSourceStatuses({ sources: [{ ...status, failingSince: "invalid" }] })).toBeNull();
  expect(parseSourceStatuses({ sources: [{ ...status, warning: "true" }] })).toBeNull();
});

test("validates alert settings received from the server", () => {
  const settings = { enabled: true, time: "07:00", timeZone: "", days: [0, 1, 2, 3, 4, 5, 6], minimumRisk: "Medium" };
  expect(parseAlertSettings(settings)).toEqual(settings);
  expect(parseAlertSettings({ ...settings, days: [1, 1] })).toBeNull();
  expect(parseAlertSettings({ ...settings, days: [7] })).toBeNull();
  expect(parseAlertSettings({ ...settings, minimumRisk: "Severe" })).toBeNull();
});

test("builds inclusive local date ranges and rejects incomplete ranges", () => {
  const filters = { search: "patch & fix", category: "", risk: "High", source: "", attack: "", start: "2026-03-08", end: "2026-03-08" };
  const params = new URLSearchParams(storyFilterQuery(filters, 100));
  expect(params.get("search")).toBe("patch & fix");
  expect(params.get("offset")).toBe("100");
  const start = new Date(params.get("after")!);
  const end = new Date(params.get("before")!);
  expect(start.getDate()).toBe(8);
  expect(start.getHours()).toBe(0);
  expect(end.getDate()).toBe(9);
  expect(end.getHours()).toBe(0);
  expect(() => storyFilterQuery({ ...filters, end: "" }, 0)).toThrow("both");
  expect(() => storyFilterQuery({ ...filters, end: "2026-03-07" }, 0)).toThrow("valid");
});

test("accepts only well-formed reset tokens from the URL fragment", () => {
  expect(parseResetToken("#reset=abcDEF123")).toBe("abcDEF123");
  expect(parseResetToken("#reset=<script>")).toBe("");
  expect(parseResetToken("")).toBe("");
});

test("shows the required NVD, MITRE, and Have I Been Pwned notices", () => {
  const markup = renderToStaticMarkup(createElement(DashboardNotices));
  expect(markup).toContain("This product uses the NVD API but is not endorsed or certified by the NVD.");
  expect(markup).toContain("© 2026 The MITRE Corporation.");
  expect(markup).toContain("https://attack.mitre.org/resources/legal-and-branding/terms-of-use/");
  expect(markup).toContain("https://haveibeenpwned.com");
});
