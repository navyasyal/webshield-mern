import { chromium } from "playwright";
import { validateLabUrl } from "./security.js";

export async function dynamicCrawl(rawUrl) {
  const startUrl = validateLabUrl(rawUrl);
  const origin = new URL(startUrl).origin;

  const discoveredPages = new Set();
  const discoveredApis = new Map();
  const discoveredForms = [];

  const queue = [startUrl];

  const browser = await chromium.launch({
    headless: true,
  });

  const context = await browser.newContext({
    serviceWorkers: "block",
  });

  const page = await context.newPage();

  page.setDefaultTimeout(5000);
  page.setDefaultNavigationTimeout(10000);

  // Discover XHR/fetch requests made by the page
  page.on("request", (request) => {
    try {
      const requestUrl = new URL(request.url());

      if (requestUrl.origin !== origin) {
        return;
      }

      const type = request.resourceType();

      if (type === "xhr" || type === "fetch") {
        const key = `${request.method()}-${requestUrl}`;

        discoveredApis.set(key, {
          url: requestUrl.toString(),
          method: request.method(),
          resourceType: type,
        });
      }
    } catch {
      // Ignore malformed URLs
    }
  });

  while (queue.length > 0 && discoveredPages.size < 10) {
    const currentUrl = queue.shift();

    if (discoveredPages.has(currentUrl)) {
      continue;
    }

    let current;

    try {
      current = new URL(currentUrl);

      if (current.origin !== origin) {
        continue;
      }

      await page.goto(current.toString(), {
        waitUntil: "domcontentloaded",
      });
    } catch {
      continue;
    }

    discoveredPages.add(current.toString());

    // -----------------------------
    // Discover links
    // -----------------------------

    const links = await page.locator("a[href]").evaluateAll(
      (elements) =>
        elements
          .map((element) => element.href)
          .filter(Boolean)
    );

    for (const link of links) {
      try {
        const next = new URL(link);

        next.hash = "";

        if (
          next.origin === origin &&
          !discoveredPages.has(next.toString())
        ) {
          queue.push(next.toString());
        }
      } catch {
        // Ignore malformed links
      }
    }

    // -----------------------------
    // Discover forms and inputs
    // -----------------------------

    const forms = await page.locator("form").evaluateAll(
      (formElements) =>
        formElements.map((form) => ({
          action: form.action || window.location.href,

          method:
            (form.method || "GET").toUpperCase(),

          inputs: Array.from(
            form.querySelectorAll(
              "input, textarea, select"
            )
          ).map((input) => ({
            name:
              input.getAttribute("name") || "",

            type:
              input.getAttribute("type") ||
              input.tagName.toLowerCase(),
          })),
        }))
    );

    for (const form of forms) {
      try {
        const formUrl = new URL(
          form.action,
          current.toString()
        );

        if (formUrl.origin !== origin) {
          continue;
        }

        discoveredForms.push({
          page: current.toString(),
          action: formUrl.toString(),
          method: form.method,
          inputs: form.inputs,
        });
      } catch {
        // Ignore invalid forms
      }
    }
  }

  await browser.close();

  return {
    pages: [...discoveredPages],

    forms: discoveredForms,

    apiRequests: [
      ...discoveredApis.values(),
    ],
  };
}