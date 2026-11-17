import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import { App, ExternalStoryLink, getSafeExternalURL } from "./App";

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
      },
    }),
  );
  expect(markup).toContain("&lt;b&gt;untrusted&lt;/b&gt;");
  expect(markup).not.toContain("<a ");
  expect(getSafeExternalURL("https://example.org/advisory")?.hostname).toBe("example.org");
  expect(getSafeExternalURL("https://trusted.example@evil.example/")).toBeNull();
});
