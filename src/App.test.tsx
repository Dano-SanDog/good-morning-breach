import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import { App, ExternalStoryLink, getSafeExternalURL, parseStories } from "./App";

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
  expect(parsed?.[0]?.attackTechniques[0]?.url).toBe("https://attack.mitre.org/techniques/T1190/");
  expect(Object.prototype).not.toHaveProperty("polluted");

  expect(parseStories({
    stories: [{
      id: 1,
      title: "Headline",
      url: "https://example.org/advisory",
      sources: ["CERT-EU"],
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
