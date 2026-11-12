import test from "node:test";
import assert from "node:assert/strict";


// ======================================================
// Configuration
// ======================================================

const BASE_URL =
  process.env.WEBSHIELD_BASE_URL ||
  "http://localhost:8081";


const LAB_URL =
  "http://lab:4000/";


const TEST_PASSWORD =
  "WebShieldTest@123";


const TEST_EMAIL =
  `webshield-test-${Date.now()}-${process.pid}@example.test`;


// ======================================================
// HTTP Helper
// ======================================================

async function request(
  path,
  {
    method = "GET",
    body,
    cookie,
  } = {}
) {
  const headers = {
    Accept:
      "application/json",
  };


  if (
    body !== undefined
  ) {
    headers[
      "Content-Type"
    ] =
      "application/json";
  }


  if (
    cookie
  ) {
    headers.Cookie =
      cookie;
  }


  const response =
    await fetch(
      `${BASE_URL}${path}`,

      {
        method,

        headers,

        body:
          body === undefined
            ? undefined
            : JSON.stringify(
                body
              ),

        redirect:
          "manual",
      }
    );


  const contentType =
    response.headers.get(
      "content-type"
    ) ||
    "";


  let data =
    null;


  if (
    contentType.includes(
      "application/json"
    )
  ) {
    data =
      await response.json();

  } else {
    data =
      await response
        .text()
        .catch(
          () => ""
        );
  }


  const setCookie =
    response.headers.get(
      "set-cookie"
    );


  const sessionCookie =
    setCookie
      ? setCookie
          .split(";")[0]
          .trim()
      : null;


  return {
    response,
    data,
    sessionCookie,
  };
}


// ======================================================
// Sleep Helper
// ======================================================

function sleep(
  milliseconds
) {
  return new Promise(
    (
      resolve
    ) => {

      setTimeout(
        resolve,
        milliseconds
      );

    }
  );
}


// ======================================================
// Full WebShield Integration Test
// ======================================================

test(
  "WebShield end-to-end API security workflow",

  {
    timeout:
      90000,
  },

  async (
    t
  ) => {

    let sessionCookie =
      null;


    let scanId =
      null;


    // ==================================================
    // Health
    // ==================================================

    await t.test(
      "API health endpoint is available",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            "/api/health"
          );


        assert.equal(
          response.status,
          200
        );


        assert.equal(
          data.ok,
          true
        );


        assert.equal(
          data.application,
          "WebShield"
        );


        assert.equal(
          data.service,
          "API"
        );

      }
    );


    // ==================================================
    // Register
    // ==================================================

    await t.test(
      "user can register",

      async () => {

        const {
          response,
          data,
          sessionCookie:
            cookie,
        } =
          await request(
            "/api/auth/register",

            {
              method:
                "POST",

              body: {
                email:
                  TEST_EMAIL,

                password:
                  TEST_PASSWORD,
              },
            }
          );


        assert.equal(
          response.status,
          201
        );


        assert.equal(
          data.email,
          TEST_EMAIL
        );


        assert.ok(
          cookie,
          "Authentication cookie should be returned"
        );


        sessionCookie =
          cookie;

      }
    );


    // ==================================================
    // Current User
    // ==================================================

    await t.test(
      "authenticated user can access profile",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            "/api/me",

            {
              cookie:
                sessionCookie,
            }
          );


        assert.equal(
          response.status,
          200
        );


        assert.equal(
          data.email,
          TEST_EMAIL
        );

      }
    );


    // ==================================================
    // Logout
    // ==================================================

    await t.test(
      "user can logout",

      async () => {

        const {
          response,
        } =
          await request(
            "/api/auth/logout",

            {
              method:
                "POST",

              cookie:
                sessionCookie,
            }
          );


        assert.equal(
          response.status,
          200
        );

      }
    );


    // ==================================================
    // Login
    // ==================================================

    await t.test(
      "registered user can login again",

      async () => {

        const {
          response,
          data,
          sessionCookie:
            cookie,
        } =
          await request(
            "/api/auth/login",

            {
              method:
                "POST",

              body: {
                email:
                  TEST_EMAIL,

                password:
                  TEST_PASSWORD,
              },
            }
          );


        assert.equal(
          response.status,
          200
        );


        assert.equal(
          data.email,
          TEST_EMAIL
        );


        assert.ok(
          cookie
        );


        sessionCookie =
          cookie;

      }
    );


    // ==================================================
    // Authentication Protection
    // ==================================================

    await t.test(
      "scan creation rejects unauthenticated users",

      async () => {

        const {
          response,
        } =
          await request(
            "/api/scans",

            {
              method:
                "POST",

              body: {
                url:
                  LAB_URL,

                authorized:
                  true,
              },
            }
          );


        assert.equal(
          response.status,
          401
        );

      }
    );


    // ==================================================
    // Authorization Confirmation
    // ==================================================

    await t.test(
      "scan creation requires authorization confirmation",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            "/api/scans",

            {
              method:
                "POST",

              cookie:
                sessionCookie,

              body: {
                url:
                  LAB_URL,

                authorized:
                  false,
              },
            }
          );


        assert.equal(
          response.status,
          400
        );


        assert.match(
          String(
            data.error
          ),
          /authorization/i
        );

      }
    );


    // ==================================================
    // External Target Protection
    // ==================================================

    await t.test(
      "scanner blocks arbitrary external targets",

      async () => {

        const {
          response,
        } =
          await request(
            "/api/scans",

            {
              method:
                "POST",

              cookie:
                sessionCookie,

              body: {
                url:
                  "https://example.com/",

                authorized:
                  true,
              },
            }
          );


        assert.notEqual(
          response.status,
          202,
          "External target must never be queued"
        );


        assert.ok(
          response.status >=
            400
        );

      }
    );


    // ==================================================
    // Valid Controlled Scan
    // ==================================================

    await t.test(
      "authorized controlled lab scan can be queued",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            "/api/scans",

            {
              method:
                "POST",

              cookie:
                sessionCookie,

              body: {
                url:
                  LAB_URL,

                authorized:
                  true,
              },
            }
          );


        assert.equal(
          response.status,
          202
        );


        assert.ok(
          data.id,
          "Scan ID should be returned"
        );


        scanId =
          String(
            data.id
          );

      }
    );


    // ==================================================
    // Scan Ownership / Retrieval
    // ==================================================

    await t.test(
      "created scan can be retrieved by its owner",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            `/api/scans/${scanId}`,

            {
              cookie:
                sessionCookie,
            }
          );


        assert.equal(
          response.status,
          200
        );


        assert.equal(
          String(
            data._id
          ),
          scanId
        );


        assert.equal(
          data.url,
          LAB_URL
        );


        assert.ok(
          [
            "queued",
            "running",
            "completed",
          ].includes(
            data.status
          )
        );

      }
    );


    // ==================================================
    // BullMQ + Worker + Scanner
    // ==================================================

    await t.test(
      "worker processes the scan to completion",

      async () => {

        let completedScan =
          null;


        for (
          let attempt = 0;
          attempt <
          40;
          attempt +=
          1
        ) {

          const {
            response,
            data,
          } =
            await request(
              `/api/scans/${scanId}`,

              {
                cookie:
                  sessionCookie,
              }
            );


          assert.equal(
            response.status,
            200
          );


          if (
            data.status ===
            "failed"
          ) {
            assert.fail(
              `Scan failed: ${
                data.error ||
                "Unknown worker error"
              }`
            );
          }


          if (
            data.status ===
            "completed"
          ) {
            completedScan =
              data;

            break;
          }


          await sleep(
            1500
          );
        }


        assert.ok(
          completedScan,
          "Scan did not complete within the test timeout"
        );


        assert.equal(
          completedScan.status,
          "completed"
        );


        assert.equal(
          completedScan
            .progress
            ?.percent,
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
          "Controlled vulnerable lab should produce findings"
        );


        assert.equal(
          typeof completedScan.securityScore,
          "number"
        );


        assert.ok(
          completedScan.comparison,
          "Regression comparison data should exist"
        );

      }
    );


    // ==================================================
    // Expected Security Findings
    // ==================================================

    await t.test(
      "scanner detects expected controlled-lab vulnerabilities",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            `/api/scans/${scanId}`,

            {
              cookie:
                sessionCookie,
            }
          );


        assert.equal(
          response.status,
          200
        );


        const findingCodes =
          new Set(
            (
              data.findings ||
              []
            ).map(
              (
                finding
              ) =>
                finding.code
            )
          );


        assert.ok(
          findingCodes.has(
            "REFLECTED_XSS"
          ),
          "Reflected XSS should be detected"
        );


        assert.ok(
          findingCodes.has(
            "OPEN_REDIRECT"
          ),
          "Open Redirect should be detected"
        );


        assert.ok(
          findingCodes.has(
            "EXPOSED_ENV"
          ),
          "Exposed environment file should be detected"
        );


        assert.ok(
          findingCodes.has(
            "CORS_ARBITRARY_ORIGIN_CREDENTIALS"
          ),
          "Dangerous CORS configuration should be detected"
        );

      }
    );


    // ==================================================
    // Professional PDF Report
    // ==================================================

    await t.test(
      "completed scan generates a PDF report",

      async () => {

        const response =
          await fetch(
            `${BASE_URL}/api/scans/${scanId}/report`,

            {
              headers: {
                Cookie:
                  sessionCookie,
              },
            }
          );


        assert.equal(
          response.status,
          200
        );


        const contentType =
          response.headers.get(
            "content-type"
          ) ||
          "";


        assert.match(
          contentType,
          /application\/pdf/i
        );


        const buffer =
          Buffer.from(
            await response.arrayBuffer()
          );


        assert.ok(
          buffer.length >
            1000,
          "Generated PDF should not be empty"
        );


        const signature =
          buffer
            .subarray(
              0,
              4
            )
            .toString();


        assert.equal(
          signature,
          "%PDF"
        );

      }
    );


    // ==================================================
    // Scan History
    // ==================================================

    await t.test(
      "completed scan appears in scan history",

      async () => {

        const {
          response,
          data,
        } =
          await request(
            "/api/scans",

            {
              cookie:
                sessionCookie,
            }
          );


        assert.equal(
          response.status,
          200
        );


        assert.ok(
          Array.isArray(
            data
          )
        );


        assert.ok(
          data.some(
            (
              scan
            ) =>
              String(
                scan._id
              ) ===
              scanId
          )
        );

      }
    );

  }
);