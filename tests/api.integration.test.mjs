import test from "node:test";
import assert from "node:assert/strict";


// ======================================================
// Configuration
// ======================================================

const BASE_URL =
  process.env.BASE_URL ||
  "http://localhost:8081";


const TEST_PASSWORD =
  "WebShieldTest@123";


const TEST_EMAIL =
  `webshield-ci-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2, 8)}@example.com`;


// ======================================================
// Session Cookie
// ======================================================

let sessionCookie =
  "";


// ======================================================
// Helpers
// ======================================================

function getSetCookieHeaders(
  response
) {
  if (
    typeof response.headers.getSetCookie ===
    "function"
  ) {
    return response.headers.getSetCookie();
  }


  const value =
    response.headers.get(
      "set-cookie"
    );


  return value
    ? [value]
    : [];
}


function updateSessionCookie(
  response
) {
  const setCookieHeaders =
    getSetCookieHeaders(
      response
    );


  for (
    const header
    of setCookieHeaders
  ) {
    const firstPart =
      header
        .split(";")[0]
        .trim();


    if (
      firstPart.startsWith(
        "ws_token="
      )
    ) {
      sessionCookie =
        firstPart;
    }
  }
}


async function request(
  path,
  options = {}
) {
  const headers = {
    ...(options.headers || {}),
  };


  if (
    options.body &&
    !headers[
      "Content-Type"
    ]
  ) {
    headers[
      "Content-Type"
    ] =
      "application/json";
  }


  if (
    sessionCookie
  ) {
    headers.Cookie =
      sessionCookie;
  }


  const response =
    await fetch(
      `${BASE_URL}${path}`,
      {
        redirect:
          "manual",

        ...options,

        headers,
      }
    );


  updateSessionCookie(
    response
  );


  return response;
}


async function json(
  response
) {
  const body =
    await response.text();


  if (!body) {
    return {};
  }


  try {
    return JSON.parse(
      body
    );
  } catch {
    throw new Error(
      `Expected JSON response but received: ${body.slice(
        0,
        300
      )}`
    );
  }
}


async function waitForCompletedScan(
  scanId
) {
  const attempts =
    80;


  for (
    let attempt = 1;
    attempt <= attempts;
    attempt += 1
  ) {
    const response =
      await request(
        `/api/scans/${scanId}`
      );


    assert.equal(
      response.status,
      200,
      `Unable to retrieve scan during polling. HTTP ${response.status}`
    );


    const scan =
      await json(
        response
      );


    console.log(
      `[poll ${attempt}/${attempts}] ${scan.status} - ${scan.progress?.percent ?? 0}% - ${scan.progress?.stage ?? ""}`
    );


    if (
      scan.status ===
      "completed"
    ) {
      return scan;
    }


    if (
      scan.status ===
      "failed"
    ) {
      throw new Error(
        `Scan failed: ${scan.error || "Unknown scanner error"}`
      );
    }


    await new Promise(
      (
        resolve
      ) =>
        setTimeout(
          resolve,
          1500
        )
    );
  }


  throw new Error(
    "Timed out waiting for WebShield scan to complete"
  );
}


// ======================================================
// Full WebShield Integration Workflow
// ======================================================

test(
  "WebShield deployed application integration workflow",

  {
    timeout:
      180000,
  },

  async () => {

    console.log(
      `Testing WebShield at ${BASE_URL}`
    );


    // ==================================================
    // Health
    // ==================================================

    const healthResponse =
      await request(
        "/api/health"
      );


    assert.equal(
      healthResponse.status,
      200
    );


    const health =
      await json(
        healthResponse
      );


    assert.equal(
      health.ok,
      true
    );


    assert.equal(
      health.application,
      "WebShield"
    );


    // ==================================================
    // Register
    // ==================================================

    const registerResponse =
      await request(
        "/api/auth/register",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              email:
                TEST_EMAIL,

              password:
                TEST_PASSWORD,
            }),
        }
      );


    assert.equal(
      registerResponse.status,
      201
    );


    assert.ok(
      sessionCookie.startsWith(
        "ws_token="
      ),
      "Registration should create ws_token cookie"
    );


    const registeredUser =
      await json(
        registerResponse
      );


    assert.equal(
      registeredUser.email,
      TEST_EMAIL
    );


    // ==================================================
    // Current User
    // ==================================================

    const meResponse =
      await request(
        "/api/me"
      );


    assert.equal(
      meResponse.status,
      200
    );


    const me =
      await json(
        meResponse
      );


    assert.equal(
      me.email,
      TEST_EMAIL
    );


    // ==================================================
    // Logout
    // ==================================================

    const logoutResponse =
      await request(
        "/api/auth/logout",

        {
          method:
            "POST",
        }
      );


    assert.equal(
      logoutResponse.status,
      200
    );


    sessionCookie =
      "";


    // ==================================================
    // Login
    // ==================================================

    const loginResponse =
      await request(
        "/api/auth/login",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              email:
                TEST_EMAIL,

              password:
                TEST_PASSWORD,
            }),
        }
      );


    assert.equal(
      loginResponse.status,
      200
    );


    assert.ok(
      sessionCookie.startsWith(
        "ws_token="
      ),
      "Login should create ws_token cookie"
    );


    // ==================================================
    // Protected API Must Reject Anonymous User
    // ==================================================

    const savedCookie =
      sessionCookie;


    sessionCookie =
      "";


    const unauthenticatedScanResponse =
      await request(
        "/api/scans",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              url:
                "http://lab:4000/",

              authorized:
                true,
            }),
        }
      );


    assert.equal(
      unauthenticatedScanResponse.status,
      401
    );


    sessionCookie =
      savedCookie;


    // ==================================================
    // Authorization Confirmation Required
    // ==================================================

    const unauthorizedTargetResponse =
      await request(
        "/api/scans",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              url:
                "http://lab:4000/",

              authorized:
                false,
            }),
        }
      );


    assert.equal(
      unauthorizedTargetResponse.status,
      400
    );


    // ==================================================
    // Public / External Target Must Be Blocked
    // ==================================================

    const externalResponse =
      await request(
        "/api/scans",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              url:
                "https://example.com/",

              authorized:
                true,
            }),
        }
      );


    assert.ok(
      externalResponse.status >=
      400,
      "External target must not be accepted"
    );


    assert.notEqual(
      externalResponse.status,
      202
    );


    // ==================================================
    // Create Controlled Lab Scan
    // ==================================================

    const createScanResponse =
      await request(
        "/api/scans",

        {
          method:
            "POST",

          body:
            JSON.stringify({
              url:
                "http://lab:4000/",

              authorized:
                true,
            }),
        }
      );


    assert.equal(
      createScanResponse.status,
      202
    );


    const createdScan =
      await json(
        createScanResponse
      );


    assert.ok(
      createdScan.id,
      "Scan ID should be returned"
    );


    const scanId =
      String(
        createdScan.id
      );


    // ==================================================
    // Scan Ownership / Retrieval
    // ==================================================

    const queuedResponse =
      await request(
        `/api/scans/${scanId}`
      );


    assert.equal(
      queuedResponse.status,
      200
    );


    const queuedScan =
      await json(
        queuedResponse
      );


    assert.equal(
      String(
        queuedScan._id
      ),
      scanId
    );


    // ==================================================
    // Wait for Worker
    // ==================================================

    const completedScan =
      await waitForCompletedScan(
        scanId
      );


    assert.equal(
      completedScan.status,
      "completed"
    );


    assert.equal(
      completedScan.progress?.percent,
      100
    );


    assert.ok(
      Array.isArray(
        completedScan.findings
      )
    );


    assert.ok(
      completedScan.findings.length >
      0,
      "Completed scan should contain findings"
    );


    assert.equal(
      typeof completedScan.securityScore,
      "number"
    );


    assert.ok(
      completedScan.comparison,
      "Regression comparison should exist"
    );


    // ==================================================
    // Expected Vulnerabilities
    // ==================================================

    const findingCodes =
      new Set(
        completedScan.findings
          .map(
            (
              finding
            ) =>
              finding.code
          )
          .filter(
            Boolean
          )
      );


    const expectedFindingCodes = [
      "REFLECTED_XSS",
      "OPEN_REDIRECT",
      "EXPOSED_ENV",
      "CORS_ARBITRARY_ORIGIN_CREDENTIALS",
    ];


    for (
      const code
      of expectedFindingCodes
    ) {
      assert.ok(
        findingCodes.has(
          code
        ),
        `Expected finding was not detected: ${code}`
      );
    }


    // ==================================================
    // Dynamic Discovery
    // ==================================================

    assert.ok(
      Array.isArray(
        completedScan.pages
      )
    );


    assert.ok(
      completedScan.pages.length >
      0
    );


    assert.ok(
      Array.isArray(
        completedScan.discovery?.forms
      )
    );


    assert.ok(
      Array.isArray(
        completedScan.discovery?.apiRequests
      )
    );


    // ==================================================
    // PDF Report
    // ==================================================

    const reportResponse =
      await request(
        `/api/scans/${scanId}/report`
      );


    assert.equal(
      reportResponse.status,
      200
    );


    const contentType =
      reportResponse.headers.get(
        "content-type"
      ) ||
      "";


    assert.ok(
      contentType.includes(
        "application/pdf"
      )
    );


    const reportBuffer =
      Buffer.from(
        await reportResponse.arrayBuffer()
      );


    assert.ok(
      reportBuffer.length >
      1000,
      "PDF report should contain substantial content"
    );


    assert.equal(
      reportBuffer
        .subarray(
          0,
          4
        )
        .toString(),
      "%PDF"
    );


    // ==================================================
    // Scan History
    // ==================================================

    const historyResponse =
      await request(
        "/api/scans"
      );


    assert.equal(
      historyResponse.status,
      200
    );


    const history =
      await json(
        historyResponse
      );


    assert.ok(
      Array.isArray(
        history
      )
    );


    assert.ok(
      history.some(
        (
          scan
        ) =>
          String(
            scan._id
          ) ===
          scanId
      ),
      "Completed scan should appear in scan history"
    );


    console.log(
      "WebShield integration workflow passed."
    );

    console.log(
      `Scan ID: ${scanId}`
    );

    console.log(
      `Findings: ${completedScan.findings.length}`
    );

    console.log(
      `Security Score: ${completedScan.securityScore}/100`
    );

  }
);