import test from "node:test";
import assert from "node:assert/strict";


// ======================================================
// Test Environment
// ======================================================

// security.js may read this environment variable
// while the module is being loaded.

process.env.SCAN_ALLOWED_HOSTS =
  "lab";


// Dynamic import ensures the environment variable above
// exists before security.js is evaluated.

const {
  validateLabUrl,
} = await import(
  "../server/src/security.js"
);


// ======================================================
// Valid Controlled Lab Target
// ======================================================

test(
  "allows the authorized WebShield lab target",

  () => {

    const result =
      validateLabUrl(
        "http://lab:4000/"
      );


    assert.ok(
      result,
      "Lab URL should be accepted"
    );

  }
);


// ======================================================
// Lab Route
// ======================================================

test(
  "allows routes inside the controlled lab",

  () => {

    const result =
      validateLabUrl(
        "http://lab:4000/search?q=test"
      );


    assert.ok(
      result,
      "Lab route should be accepted"
    );

  }
);


// ======================================================
// External Target Blocking
// ======================================================

test(
  "rejects arbitrary external websites",

  () => {

    assert.throws(
      () => {

        validateLabUrl(
          "https://example.com/"
        );

      }
    );

  }
);


// ======================================================
// Hostname Bypass Protection
// ======================================================

test(
  "rejects hostname suffix bypass attempts",

  () => {

    assert.throws(
      () => {

        validateLabUrl(
          "http://lab.evil.example:4000/"
        );

      }
    );

  }
);


// ======================================================
// Localhost Bypass Protection
// ======================================================

test(
  "rejects localhost when only lab is authorized",

  () => {

    assert.throws(
      () => {

        validateLabUrl(
          "http://127.0.0.1:4000/"
        );

      }
    );

  }
);


// ======================================================
// Unsupported Protocol
// ======================================================

test(
  "rejects unsupported URL protocols",

  () => {

    assert.throws(
      () => {

        validateLabUrl(
          "file:///etc/passwd"
        );

      }
    );

  }
);