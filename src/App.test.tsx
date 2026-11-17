import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, test } from "vitest";
import { App } from "./App";

test("renders the application title", () => {
  const markup = renderToStaticMarkup(createElement(App));
  expect(markup).toContain("Good Morning Breach");
});
