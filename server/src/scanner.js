import crypto from "node:crypto";
import * as cheerio from "cheerio";

import {
  validateLabUrl,
} from "./security.js";


// ======================================================
// Configuration
// ======================================================

const MAX_PAGES = 20;

const REQUEST_TIMEOUT = 8000;

const MAX_REDIRECTS = 5;


// ======================================================
// Finding Helpers
// ======================================================

function fingerprint(
  code,
  url,
  extra = ""
) {
  return crypto
    .createHash("sha256")
    .update(
      `${code}|${url}|${extra}`
    )
    .digest("hex");
}


function createFinding({
  code,
  title,
  severity,
  confidence,
  owasp,
  url,
  evidence,
  remediation,
  extra = "",
}) {
  return {
    code,
    title,
    severity,
    confidence,
    owasp,
    url,
    evidence,
    remediation,

    fingerprint:
      fingerprint(
        code,
        url,
        extra
      ),

    status:
      "Open",

    firstSeen:
      new Date(),

    lastSeen:
      new Date(),

    occurrenceCount:
      1,
  };
}


// ======================================================
// Safe HTTP Request
//
// Every redirect is checked again against the
// controlled-lab allowlist.
// ======================================================

async function safeFetch(
  rawUrl,
  options = {}
) {
  const {
    headers = {},
    followRedirects = true,
    ...rest
  } = options;


  let currentUrl =
    validateLabUrl(
      rawUrl
    );


  for (
    let redirectCount = 0;
    redirectCount <= MAX_REDIRECTS;
    redirectCount += 1
  ) {
    const controller =
      new AbortController();


    const timer =
      setTimeout(
        () =>
          controller.abort(),
        REQUEST_TIMEOUT
      );


    let response;


    try {
      response =
        await fetch(
          currentUrl,
          {
            ...rest,

            redirect:
              "manual",

            signal:
              controller.signal,

            headers: {
              "User-Agent":
                "WebShield-Capstone-Scanner/1.0",

              ...headers,
            },
          }
        );

    } finally {
      clearTimeout(
        timer
      );
    }


    const isRedirect =
      [
        301,
        302,
        303,
        307,
        308,
      ].includes(
        response.status
      );


    if (
      !isRedirect ||
      !followRedirects
    ) {
      return response;
    }


    const location =
      response.headers.get(
        "location"
      );


    if (!location) {
      return response;
    }


    const nextUrl =
      new URL(
        location,
        currentUrl
      );


    // Important:
    // prevents redirects outside the
    // explicitly permitted lab.
    currentUrl =
      validateLabUrl(
        nextUrl.toString()
      );
  }


  throw new Error(
    "Too many redirects"
  );
}


// ======================================================
// Passive Header Checks
// ======================================================

function checkHeaders(
  url,
  response
) {
  const findings = [];

  const headers =
    response.headers;


  // ----------------------------------------------------
  // Content Security Policy
  // ----------------------------------------------------

  if (
    !headers.get(
      "content-security-policy"
    )
  ) {
    findings.push(
      createFinding({
        code:
          "MISSING_CSP",

        title:
          "Missing Content Security Policy",

        severity:
          "Medium",

        confidence:
          "High",

        owasp:
          "A05: Security Misconfiguration",

        url,

        evidence:
          "Content-Security-Policy header is absent.",

        remediation:
          "Configure a restrictive Content-Security-Policy header.",
      })
    );
  }


  // ----------------------------------------------------
  // X-Content-Type-Options
  // ----------------------------------------------------

  if (
    headers
      .get(
        "x-content-type-options"
      )
      ?.toLowerCase() !==
    "nosniff"
  ) {
    findings.push(
      createFinding({
        code:
          "MISSING_NOSNIFF",

        title:
          "Missing X-Content-Type-Options",

        severity:
          "Low",

        confidence:
          "High",

        owasp:
          "A05: Security Misconfiguration",

        url,

        evidence:
          "X-Content-Type-Options: nosniff is not configured.",

        remediation:
          "Configure X-Content-Type-Options: nosniff.",
      })
    );
  }


  // ----------------------------------------------------
  // Referrer Policy
  // ----------------------------------------------------

  if (
    !headers.get(
      "referrer-policy"
    )
  ) {
    findings.push(
      createFinding({
        code:
          "MISSING_REFERRER_POLICY",

        title:
          "Missing Referrer-Policy",

        severity:
          "Low",

        confidence:
          "High",

        owasp:
          "A05: Security Misconfiguration",

        url,

        evidence:
          "Referrer-Policy header is absent.",

        remediation:
          "Configure a Referrer-Policy such as strict-origin-when-cross-origin.",
      })
    );
  }


  // ----------------------------------------------------
  // Permissions Policy
  // ----------------------------------------------------

  if (
    !headers.get(
      "permissions-policy"
    )
  ) {
    findings.push(
      createFinding({
        code:
          "MISSING_PERMISSIONS_POLICY",

        title:
          "Missing Permissions-Policy",

        severity:
          "Low",

        confidence:
          "High",

        owasp:
          "A05: Security Misconfiguration",

        url,

        evidence:
          "Permissions-Policy header is absent.",

        remediation:
          "Configure Permissions-Policy to restrict unnecessary browser capabilities.",
      })
    );
  }


  // ----------------------------------------------------
  // HTTP
  // ----------------------------------------------------

  if (
    new URL(
      url
    ).protocol ===
    "http:"
  ) {
    findings.push(
      createFinding({
        code:
          "HTTP_ONLY",

        title:
          "Application Uses Unencrypted HTTP",

        severity:
          "Medium",

        confidence:
          "High",

        owasp:
          "A02: Cryptographic Failures",

        url,

        evidence:
          "The application is served using HTTP rather than HTTPS.",

        remediation:
          "Deploy the application over HTTPS and redirect HTTP traffic to HTTPS.",
      })
    );
  }


  // ----------------------------------------------------
  // Technology Disclosure
  // ----------------------------------------------------

  const poweredBy =
    headers.get(
      "x-powered-by"
    );


  if (poweredBy) {
    findings.push(
      createFinding({
        code:
          "TECH_DISCLOSURE",

        title:
          "Technology Information Disclosure",

        severity:
          "Low",

        confidence:
          "High",

        owasp:
          "A05: Security Misconfiguration",

        url,

        evidence:
          `X-Powered-By header exposes server technology: ${poweredBy}`,

        remediation:
          "Disable unnecessary framework and server identification headers.",
      })
    );
  }


  // ----------------------------------------------------
  // Cookies
  // ----------------------------------------------------

  let cookies = [];


  if (
    typeof headers
      .getSetCookie ===
    "function"
  ) {
    cookies =
      headers.getSetCookie();

  } else {
    const cookie =
      headers.get(
        "set-cookie"
      );


    if (cookie) {
      cookies = [
        cookie,
      ];
    }
  }


  for (
    const cookie of cookies
  ) {
    if (
      !/httponly/i.test(
        cookie
      )
    ) {
      findings.push(
        createFinding({
          code:
            "COOKIE_NO_HTTPONLY",

          title:
            "Cookie Missing HttpOnly",

          severity:
            "Medium",

          confidence:
            "High",

          owasp:
            "A05: Security Misconfiguration",

          url,

          evidence:
            "A response cookie was issued without the HttpOnly attribute.",

          remediation:
            "Set HttpOnly on session and authentication cookies.",
        })
      );
    }


    if (
      !/samesite/i.test(
        cookie
      )
    ) {
      findings.push(
        createFinding({
          code:
            "COOKIE_NO_SAMESITE",

          title:
            "Cookie Missing SameSite",

          severity:
            "Low",

          confidence:
            "High",

          owasp:
            "A05: Security Misconfiguration",

          url,

          evidence:
            "A response cookie was issued without a SameSite attribute.",

          remediation:
            "Configure SameSite=Lax or SameSite=Strict where appropriate.",
        })
      );
    }
  }


  return findings;
}


// ======================================================
// Sensitive File Exposure Detection
// ======================================================

async function testSensitiveFiles(
  startUrl
) {
  const findings = [];

  const origin =
    new URL(
      startUrl
    ).origin;


  const probes = [
    {
      path:
        "/.env",

      code:
        "EXPOSED_ENV",

      title:
        "Exposed Environment Configuration File",

      severity:
        "High",

      owasp:
        "A05: Security Misconfiguration",

      indicators: [
        "DB_PASSWORD=",
        "JWT_SECRET=",
      ],

      evidence:
        "A publicly accessible .env-style configuration file exposed application configuration values.",

      remediation:
        "Never place environment files inside publicly accessible web directories. Block access to dotfiles and store secrets outside the web root.",
    },

    {
      path:
        "/config.json",

      code:
        "EXPOSED_CONFIG",

      title:
        "Exposed Application Configuration",

      severity:
        "Medium",

      owasp:
        "A05: Security Misconfiguration",

      indicators: [
        "databaseUri",
        "debug",
      ],

      evidence:
        "A publicly accessible configuration file exposed internal application configuration.",

      remediation:
        "Keep internal configuration files outside the public web root and expose only configuration required by the client.",
    },

    {
      path:
        "/backup/config.bak",

      code:
        "EXPOSED_BACKUP",

      title:
        "Exposed Backup Configuration File",

      severity:
        "High",

      owasp:
        "A05: Security Misconfiguration",

      indicators: [
        "BACKUP_DATABASE_PASSWORD",
        "BACKUP_API_KEY",
      ],

      evidence:
        "A backup configuration file was directly accessible from the web application.",

      remediation:
        "Remove backup files from public directories and deny access to backup extensions such as .bak, .old and .backup.",
    },
  ];


  for (
    const probe of probes
  ) {
    const target =
      new URL(
        probe.path,
        origin
      );


    try {
      const response =
        await safeFetch(
          target.toString()
        );


      if (
        response.status !==
        200
      ) {
        continue;
      }


      const body =
        await response.text();


      const matched =
        probe.indicators
          .every(
            (indicator) =>
              body.includes(
                indicator
              )
          );


      if (!matched) {
        continue;
      }


      findings.push(
        createFinding({
          code:
            probe.code,

          title:
            probe.title,

          severity:
            probe.severity,

          confidence:
            "High",

          owasp:
            probe.owasp,

          url:
            target.toString(),

          evidence:
            probe.evidence,

          remediation:
            probe.remediation,
        })
      );

    } catch (
      error
    ) {
      console.error(
        `Sensitive-file check failed for ${probe.path}:`,
        error.message
      );
    }
  }


  return findings;
}


// ======================================================
// CORS Check
// ======================================================

async function testCors(
  url
) {
  const findings = [];

  const testOrigin =
    "https://attacker.example";


  try {
    const response =
      await safeFetch(
        url,
        {
          headers: {
            Origin:
              testOrigin,
          },
        }
      );


    const allowOrigin =
      response.headers.get(
        "access-control-allow-origin"
      );


    const allowCredentials =
      response.headers
        .get(
          "access-control-allow-credentials"
        )
        ?.toLowerCase();


    if (
      allowOrigin ===
        testOrigin &&
      allowCredentials ===
        "true"
    ) {
      findings.push(
        createFinding({
          code:
            "CORS_ARBITRARY_ORIGIN_CREDENTIALS",

          title:
            "Dangerous CORS Configuration",

          severity:
            "High",

          confidence:
            "High",

          owasp:
            "A05: Security Misconfiguration",

          url,

          evidence:
            `Server trusted arbitrary Origin "${testOrigin}" and enabled credentialed cross-origin requests.`,

          remediation:
            "Use a strict allowlist of trusted origins and never reflect arbitrary origins when credentials are enabled.",
        })
      );


      return findings;
    }


    if (
      allowOrigin ===
      testOrigin
    ) {
      findings.push(
        createFinding({
          code:
            "CORS_ORIGIN_REFLECTION",

          title:
            "Permissive CORS Origin Reflection",

          severity:
            "Medium",

          confidence:
            "High",

          owasp:
            "A05: Security Misconfiguration",

          url,

          evidence:
            `Server reflected the untrusted Origin "${testOrigin}".`,

          remediation:
            "Validate Origin values against a strict allowlist.",
        })
      );


      return findings;
    }


    if (
      allowOrigin ===
      "*"
    ) {
      findings.push(
        createFinding({
          code:
            "CORS_WILDCARD",

          title:
            "Wildcard CORS Policy",

          severity:
            "Medium",

          confidence:
            "High",

          owasp:
            "A05: Security Misconfiguration",

          url,

          evidence:
            "Access-Control-Allow-Origin is configured as wildcard (*).",

          remediation:
            "Restrict cross-origin access to explicitly trusted origins.",
        })
      );
    }

  } catch (
    error
  ) {
    console.error(
      `CORS check failed for ${url}:`,
      error.message
    );
  }


  return findings;
}


// ======================================================
// Reflected XSS Check
// ======================================================

async function testReflectedXss(
  pageUrl,
  $,
  alreadyTested
) {
  const findings = [];

  const page =
    new URL(
      pageUrl
    );


  const forms =
    $("form")
      .toArray();


  for (
    const formElement of forms
  ) {
    const form =
      $(formElement);


    const method =
      (
        form.attr(
          "method"
        ) ||
        "GET"
      ).toUpperCase();


    if (
      method !==
      "GET"
    ) {
      continue;
    }


    let action;


    try {
      action =
        new URL(
          form.attr(
            "action"
          ) ||
          pageUrl,

          pageUrl
        );


      if (
        action.origin !==
        page.origin
      ) {
        continue;
      }


      validateLabUrl(
        action.toString()
      );

    } catch {
      continue;
    }


    const candidates = [];


    form
      .find(
        "input[name], textarea[name]"
      )
      .each(
        (
          index,
          element
        ) => {

          const input =
            $(element);


          const name =
            input.attr(
              "name"
            );


          if (!name) {
            return;
          }


          const tag =
            element
              .tagName
              ?.toLowerCase();


          const type =
            (
              input.attr(
                "type"
              ) ||
              (
                tag ===
                "textarea"
                  ? "textarea"
                  : "text"
              )
            )
              .toLowerCase();


          const allowedTypes =
            [
              "text",
              "search",
              "url",
              "email",
              "textarea",
            ];


          if (
            allowedTypes.includes(
              type
            )
          ) {
            candidates.push({
              name,
              type,
            });
          }
        }
      );


    for (
      const candidate
      of candidates
    ) {
      const testKey =
        `${action}|${candidate.name}`;


      if (
        alreadyTested.has(
          testKey
        )
      ) {
        continue;
      }


      alreadyTested.add(
        testKey
      );


      const marker =
        crypto
          .randomBytes(5)
          .toString("hex");


      const probe =
        `<webshield-probe data-id="${marker}">`;


      const target =
        new URL(
          action.toString()
        );


      target
        .searchParams
        .set(
          candidate.name,
          probe
        );


      try {
        const response =
          await safeFetch(
            target.toString()
          );


        const body =
          await response.text();


        if (
          body.includes(
            probe
          )
        ) {
          findings.push(
            createFinding({
              code:
                "REFLECTED_XSS",

              title:
                "Potential Reflected Cross-Site Scripting (XSS)",

              severity:
                "High",

              confidence:
                "High",

              owasp:
                "A03: Injection",

              url:
                action.toString(),

              evidence:
                `Input parameter "${candidate.name}" reflected HTML markup without output encoding.`,

              remediation:
                "HTML-encode untrusted output and use framework-safe templating instead of inserting user-controlled input directly into HTML.",

              extra:
                candidate.name,
            })
          );
        }

      } catch (
        error
      ) {
        console.error(
          "XSS check failed:",
          error.message
        );
      }
    }
  }


  return findings;
}


// ======================================================
// Open Redirect Check
// ======================================================

async function testOpenRedirect(
  pageUrl,
  $,
  alreadyTested
) {
  const findings = [];

  const page =
    new URL(
      pageUrl
    );


  const redirectParameters =
    new Set([
      "url",
      "next",
      "redirect",
      "redirecturl",
      "redirect_uri",
      "return",
      "returnurl",
      "continue",
      "destination",
    ]);


  const forms =
    $("form")
      .toArray();


  for (
    const formElement of forms
  ) {
    const form =
      $(formElement);


    const method =
      (
        form.attr(
          "method"
        ) ||
        "GET"
      ).toUpperCase();


    if (
      method !==
      "GET"
    ) {
      continue;
    }


    let action;


    try {
      action =
        new URL(
          form.attr(
            "action"
          ) ||
          pageUrl,

          pageUrl
        );


      if (
        action.origin !==
        page.origin
      ) {
        continue;
      }


      validateLabUrl(
        action.toString()
      );

    } catch {
      continue;
    }


    const inputs =
      form
        .find(
          "input[name]"
        )
        .toArray();


    for (
      const inputElement of inputs
    ) {
      const input =
        $(inputElement);


      const parameter =
        input.attr(
          "name"
        );


      if (!parameter) {
        continue;
      }


      if (
        !redirectParameters.has(
          parameter
            .toLowerCase()
        )
      ) {
        continue;
      }


      const testKey =
        `${action}|${parameter}`;


      if (
        alreadyTested.has(
          testKey
        )
      ) {
        continue;
      }


      alreadyTested.add(
        testKey
      );


      const markerDestination =
        "https://example.com/webshield-redirect-test";


      const target =
        new URL(
          action.toString()
        );


      target
        .searchParams
        .set(
          parameter,
          markerDestination
        );


      try {
        const response =
          await safeFetch(
            target.toString(),
            {
              followRedirects:
                false,
            }
          );


        const location =
          response.headers.get(
            "location"
          );


        const redirectStatus =
          [
            301,
            302,
            303,
            307,
            308,
          ].includes(
            response.status
          );


        if (
          !redirectStatus ||
          !location
        ) {
          continue;
        }


        let destination;


        try {
          destination =
            new URL(
              location,
              action.toString()
            );

        } catch {
          continue;
        }


        if (
          destination.origin !==
            page.origin &&
          destination
            .toString()
            .startsWith(
              markerDestination
            )
        ) {
          findings.push(
            createFinding({
              code:
                "OPEN_REDIRECT",

              title:
                "Open Redirect Vulnerability",

              severity:
                "Medium",

              confidence:
                "High",

              owasp:
                "A01: Broken Access Control",

              url:
                action.toString(),

              evidence:
                `Parameter "${parameter}" allowed redirection to an external destination.`,

              remediation:
                "Allow only trusted internal redirect destinations and reject arbitrary external URLs.",

              extra:
                parameter,
            })
          );
        }

      } catch (
        error
      ) {
        console.error(
          "Open redirect check failed:",
          error.message
        );
      }
    }
  }


  return findings;
}


// ======================================================
// Main Scanner
// ======================================================

export async function scanSite(
  rawUrl
) {
  const startUrl =
    validateLabUrl(
      rawUrl
    );


  const origin =
    new URL(
      startUrl
    ).origin;


  const queue = [
    startUrl,
  ];


  const visited =
    new Set();


  const pages =
    [];


  const findings =
    [];


  const findingKeys =
    new Set();


  const xssTests =
    new Set();


  const redirectTests =
    new Set();


  // ----------------------------------------------------
  // Add Finding Without Duplicates
  // ----------------------------------------------------

  function addFinding(
    finding
  ) {
    if (
      findingKeys.has(
        finding.fingerprint
      )
    ) {
      return;
    }


    findingKeys.add(
      finding.fingerprint
    );


    findings.push(
      finding
    );
  }


  // ====================================================
  // Sensitive Files
  // ====================================================

  const sensitiveFindings =
    await testSensitiveFiles(
      startUrl
    );


  for (
    const finding
    of sensitiveFindings
  ) {
    addFinding(
      finding
    );
  }


  // ====================================================
  // Crawl
  // ====================================================

  while (
    queue.length > 0 &&
    visited.size < MAX_PAGES
  ) {
    const current =
      queue.shift();


    if (
      visited.has(
        current
      )
    ) {
      continue;
    }


    let currentUrl;


    try {
      currentUrl =
        new URL(
          current
        );


      if (
        currentUrl.origin !==
        origin
      ) {
        continue;
      }


      validateLabUrl(
        currentUrl.toString()
      );

    } catch {
      continue;
    }


    visited.add(
      currentUrl.toString()
    );


    try {
      const response =
        await safeFetch(
          currentUrl.toString()
        );


      const canonicalUrl =
        currentUrl.toString();


      pages.push(
        canonicalUrl
      );


      // ----------------------------------------------
      // Passive Checks
      // ----------------------------------------------

      const passiveFindings =
        checkHeaders(
          canonicalUrl,
          response
        );


      for (
        const finding
        of passiveFindings
      ) {
        addFinding(
          finding
        );
      }


      // ----------------------------------------------
      // CORS
      // ----------------------------------------------

      const corsFindings =
        await testCors(
          canonicalUrl
        );


      for (
        const finding
        of corsFindings
      ) {
        addFinding(
          finding
        );
      }


      // ----------------------------------------------
      // HTML Only
      // ----------------------------------------------

      const contentType =
        response.headers.get(
          "content-type"
        ) ||
        "";


      if (
        !contentType.includes(
          "text/html"
        )
      ) {
        continue;
      }


      const html =
        await response.text();


      const $ =
        cheerio.load(
          html
        );


      // ----------------------------------------------
      // Reflected XSS
      // ----------------------------------------------

      const xssFindings =
        await testReflectedXss(
          canonicalUrl,
          $,
          xssTests
        );


      for (
        const finding
        of xssFindings
      ) {
        addFinding(
          finding
        );
      }


      // ----------------------------------------------
      // Open Redirect
      // ----------------------------------------------

      const redirectFindings =
        await testOpenRedirect(
          canonicalUrl,
          $,
          redirectTests
        );


      for (
        const finding
        of redirectFindings
      ) {
        addFinding(
          finding
        );
      }


      // ----------------------------------------------
      // Internal Link Discovery
      // ----------------------------------------------

      $("a[href]")
        .each(
          (
            index,
            element
          ) => {

            const href =
              $(element)
                .attr(
                  "href"
                );


            if (!href) {
              return;
            }


            try {
              const next =
                new URL(
                  href,
                  canonicalUrl
                );


              next.hash = "";


              if (
                next.origin !==
                origin
              ) {
                return;
              }


              validateLabUrl(
                next.toString()
              );


              if (
                !visited.has(
                  next.toString()
                ) &&
                !queue.includes(
                  next.toString()
                )
              ) {
                queue.push(
                  next.toString()
                );
              }

            } catch {
              // Ignore invalid links
            }
          }
        );

    } catch (
      error
    ) {
      console.error(
        `Failed to scan ${current}:`,
        error.message
      );
    }
  }


  return {
    pages: [
      ...new Set(
        pages
      ),
    ],

    findings,
  };
}