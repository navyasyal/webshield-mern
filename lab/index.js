import express from "express";


// ======================================================
// Application
// ======================================================

const app =
  express();

const PORT =
  4000;


// ======================================================
// Middleware
// ======================================================

app.use(
  express.urlencoded({
    extended: false,
  })
);


app.use(
  express.json()
);


// ======================================================
// IMPORTANT
//
// This application is intentionally vulnerable.
//
// All credentials and secrets below are FAKE demo values.
//
// This lab exists only for controlled WebShield
// scanner testing.
// ======================================================


// ======================================================
// Home
// ======================================================

app.get(
  "/",

  (
    req,
    res
  ) => {

    res.setHeader(
      "Set-Cookie",
      "lab_session=demo-session; Path=/"
    );


    res.send(`
      <!doctype html>

      <html>

        <head>

          <title>
            WebShield Vulnerable Lab
          </title>

        </head>

        <body>

          <h1>
            WebShield Vulnerable Lab
          </h1>


          <p>
            Intentionally vulnerable application
            for controlled WebShield scanner testing.
          </p>


          <nav>

            <a href="/">
              Home
            </a>

            |

            <a href="/login">
              Login
            </a>

            |

            <a href="/search">
              Search
            </a>

            |

            <a href="/redirect">
              Redirect Demo
            </a>

            |

            <a href="/api/profile">
              Profile API
            </a>

          </nav>


          <hr />


          <h2>
            Vulnerability Modules
          </h2>


          <ul>

            <li>
              Security Header Misconfiguration
            </li>

            <li>
              Weak Cookies
            </li>

            <li>
              Reflected XSS
            </li>

            <li>
              Open Redirect
            </li>

            <li>
              Unsafe CORS
            </li>

            <li>
              Sensitive File Exposure
            </li>

            <li>
              API Discovery
            </li>

          </ul>


          <h2>
            API Status
          </h2>


          <p id="api-status">
            Loading...
          </p>


          <p id="profile-status">
            Loading profile...
          </p>


          <script>

            fetch("/api/status")

              .then(
                response =>
                  response.json()
              )

              .then(
                data => {

                  document
                    .getElementById(
                      "api-status"
                    )
                    .textContent =
                      "Status API: " +
                      data.status;

                }
              );


            fetch("/api/profile")

              .then(
                response =>
                  response.json()
              )

              .then(
                data => {

                  document
                    .getElementById(
                      "profile-status"
                    )
                    .textContent =
                      "Profile API: " +
                      data.username;

                }
              );

          </script>

        </body>

      </html>
    `);
  }
);


// ======================================================
// Login
// ======================================================

app.get(
  "/login",

  (
    req,
    res
  ) => {

    const username =
      req.query.username ||
      "";


    res.send(`
      <!doctype html>

      <html>

        <head>

          <title>
            Vulnerable Login
          </title>

        </head>

        <body>

          <h1>
            Login
          </h1>


          <form
            action="/login"
            method="GET"
          >

            <label>

              Username

              <input
                type="text"
                name="username"
              />

            </label>


            <br /><br />


            <label>

              Password

              <input
                type="password"
                name="password"
              />

            </label>


            <br /><br />


            <button type="submit">
              Login
            </button>

          </form>


          ${
            username
              ? `
                <p>
                  Login attempt for:
                  ${username}
                </p>
              `
              : ""
          }


          <p>

            <a href="/">
              Back Home
            </a>

          </p>

        </body>

      </html>
    `);
  }
);


// ======================================================
// Reflected XSS Demo
// ======================================================

app.get(
  "/search",

  (
    req,
    res
  ) => {

    const query =
      req.query.q ||
      "";


    res.send(`
      <!doctype html>

      <html>

        <head>

          <title>
            Vulnerable Search
          </title>

        </head>

        <body>

          <h1>
            Search
          </h1>


          <form
            action="/search"
            method="GET"
          >

            <label>

              Search Query

              <input
                type="search"
                name="q"
              />

            </label>


            <button type="submit">
              Search
            </button>

          </form>


          ${
            query
              ? `
                <h2>
                  Search Results
                </h2>

                <p>
                  You searched for:
                  ${query}
                </p>
              `
              : ""
          }


          <p>

            <a href="/">
              Back Home
            </a>

          </p>

        </body>

      </html>
    `);
  }
);


// ======================================================
// Open Redirect Demo
// ======================================================

app.get(
  "/redirect",

  (
    req,
    res
  ) => {

    const next =
      req.query.next;


    if (next) {
      return res.redirect(
        next
      );
    }


    res.send(`
      <!doctype html>

      <html>

        <head>

          <title>
            Open Redirect Demo
          </title>

        </head>

        <body>

          <h1>
            Open Redirect
          </h1>


          <form
            action="/redirect"
            method="GET"
          >

            <label>

              Destination

              <input
                type="url"
                name="next"
                value="/"
              />

            </label>


            <button type="submit">
              Continue
            </button>

          </form>


          <p>

            <a href="/">
              Back Home
            </a>

          </p>

        </body>

      </html>
    `);
  }
);


// ======================================================
// API Status
// ======================================================

app.get(
  "/api/status",

  (
    req,
    res
  ) => {

    res.json({
      status:
        "online",

      application:
        "WebShield Vulnerable Lab",
    });
  }
);


// ======================================================
// Vulnerable CORS API
// ======================================================

app.get(
  "/api/profile",

  (
    req,
    res
  ) => {

    const origin =
      req.get(
        "origin"
      );


    if (origin) {
      res.setHeader(
        "Access-Control-Allow-Origin",
        origin
      );


      res.setHeader(
        "Access-Control-Allow-Credentials",
        "true"
      );
    }


    res.json({
      username:
        "demo-user",

      role:
        "demo-admin",

      email:
        "demo@example.local",
    });
  }
);


// ======================================================
// CORS Preflight
// ======================================================

app.options(
  "/api/profile",

  (
    req,
    res
  ) => {

    const origin =
      req.get(
        "origin"
      );


    if (origin) {
      res.setHeader(
        "Access-Control-Allow-Origin",
        origin
      );
    }


    res.setHeader(
      "Access-Control-Allow-Credentials",
      "true"
    );


    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, OPTIONS"
    );


    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type"
    );


    res.sendStatus(
      204
    );
  }
);


// ======================================================
// EXPOSED .ENV
//
// All values are deliberately fake.
// ======================================================

app.get(
  "/.env",

  (
    req,
    res
  ) => {

    res.type(
      "text/plain"
    );


    res.send(`
NODE_ENV=development
DB_HOST=mongo
DB_USERNAME=webshield_demo
DB_PASSWORD=FAKE_DEMO_PASSWORD
JWT_SECRET=FAKE_DEMO_JWT_SECRET
DEBUG=true
`);
  }
);


// ======================================================
// EXPOSED CONFIG FILE
// ======================================================

app.get(
  "/config.json",

  (
    req,
    res
  ) => {

    res.json({
      environment:
        "development",

      debug:
        true,

      databaseUri:
        "mongodb://demo:FAKE_PASSWORD@mongo:27017/demo",

      internalService:
        "http://internal-api:9000",

      note:
        "Fake configuration used only by WebShield lab",
    });
  }
);


// ======================================================
// EXPOSED BACKUP FILE
// ======================================================

app.get(
  "/backup/config.bak",

  (
    req,
    res
  ) => {

    res.type(
      "text/plain"
    );


    res.send(`
# WebShield fake backup configuration

BACKUP_DATABASE_PASSWORD=FAKE_BACKUP_PASSWORD
BACKUP_API_KEY=FAKE_BACKUP_API_KEY
BACKUP_SERVER=internal-backup.local

# This file intentionally exists for scanner testing.
`);
  }
);


// ======================================================
// 404
// ======================================================

app.use(
  (
    req,
    res
  ) => {

    res
      .status(404)
      .send(`
        <!doctype html>

        <html>

          <body>

            <h1>
              404
            </h1>

            <p>
              Page not found.
            </p>

            <a href="/">
              Home
            </a>

          </body>

        </html>
      `);
  }
);


// ======================================================
// Start Lab
// ======================================================

app.listen(
  PORT,
  "0.0.0.0",

  () => {

    console.log(
      `WebShield vulnerable lab running on port ${PORT}`
    );

  }
);