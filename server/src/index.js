import express from "express";
import http from "node:http";

import helmet from "helmet";

import cookieParser from "cookie-parser";

import rateLimit from "express-rate-limit";

import bcrypt from "bcryptjs";

import jwt from "jsonwebtoken";

import passport from "passport";

import {
  Strategy as GoogleStrategy,
} from "passport-google-oauth20";

import PDFDocument from "pdfkit";

import Redis from "ioredis";

import {
  Server,
} from "socket.io";

import {
  connectDb,
  User,
  Scan,
} from "./db.js";

import {
  auth,
  credentials,
  issueToken,
  setAuthCookie,
  validateLabUrl,
} from "./security.js";

import {
  scanQueue,
} from "./queue.js";


// ======================================================
// Configuration
// ======================================================

const PORT =
  process.env.PORT ||
  5000;

const REDIS_URL =
  process.env.REDIS_URL ||
  "redis://localhost:6379";

const PUBLIC_URL =
  process.env.PUBLIC_URL ||
  "http://localhost:8081";


// ======================================================
// Express + HTTP
// ======================================================

const app =
  express();

const server =
  http.createServer(
    app
  );


// ======================================================
// Socket.IO
// ======================================================

const io =
  new Server(
    server,
    {
      path:
        "/socket.io",

      cors: {
        origin:
          PUBLIC_URL,

        credentials:
          true,
      },
    }
  );


// ======================================================
// Redis
// ======================================================

const cache =
  new Redis(
    REDIS_URL
  );


const progressSubscriber =
  new Redis(
    REDIS_URL
  );


// ======================================================
// Express Middleware
// ======================================================

app.disable(
  "x-powered-by"
);


app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy:
        "same-origin",
    },
  })
);


app.use(
  express.json({
    limit:
      "20kb",
  })
);


app.use(
  cookieParser()
);


app.use(
  passport.initialize()
);


// ======================================================
// CSRF / Origin Protection
// ======================================================

app.use(
  (
    req,
    res,
    next
  ) => {

    const protectedMethods =
      [
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
      ];


    if (
      !protectedMethods.includes(
        req.method
      )
    ) {
      return next();
    }


    const origin =
      req.get(
        "origin"
      );


    let allowedOrigin;


    try {

      allowedOrigin =
        new URL(
          PUBLIC_URL
        ).origin;

    } catch {

      return res
        .status(500)
        .json({
          error:
            "Invalid PUBLIC_URL configuration",
        });
    }


    if (
      origin &&
      origin !==
        allowedOrigin
    ) {

      return res
        .status(403)
        .json({
          error:
            "Cross-site request blocked",
        });

    }


    next();
  }
);


// ======================================================
// Authentication Rate Limiter
// ======================================================

const authLimiter =
  rateLimit({
    windowMs:
      15 *
      60 *
      1000,

    limit:
      30,

    standardHeaders:
      "draft-7",

    legacyHeaders:
      false,

    message: {
      error:
        "Too many authentication attempts",
    },
  });


app.use(
  "/api/auth",
  authLimiter
);


// ======================================================
// Socket Cookie Parser
// ======================================================

function parseSocketCookies(
  cookieHeader = ""
) {

  const cookies = {};


  for (
    const part of
    cookieHeader.split(";")
  ) {

    const item =
      part.trim();


    if (!item) {
      continue;
    }


    const separator =
      item.indexOf("=");


    if (
      separator === -1
    ) {
      continue;
    }


    const key =
      item
        .slice(
          0,
          separator
        )
        .trim();


    const rawValue =
      item
        .slice(
          separator + 1
        )
        .trim();


    try {

      cookies[key] =
        decodeURIComponent(
          rawValue
        );

    } catch {

      cookies[key] =
        rawValue;

    }
  }


  return cookies;
}


// ======================================================
// Socket Authentication
// ======================================================

io.use(
  (
    socket,
    next
  ) => {

    try {

      const cookies =
        parseSocketCookies(
          socket.handshake
            .headers
            .cookie ||
          ""
        );


      const token =
        cookies.ws_token;


      if (!token) {

        return next(
          new Error(
            "Authentication required"
          )
        );

      }


      const payload =
        jwt.verify(
          token,
          process.env
            .JWT_SECRET,
          {
            issuer:
              "webshield",
          }
        );


      socket.userId =
        payload.sub;


      next();

    } catch (
      error
    ) {

      console.error(
        "Socket authentication failed:",
        error.message
      );


      next(
        new Error(
          "Authentication failed"
        )
      );
    }
  }
);


// ======================================================
// Socket Connection
// ======================================================

io.on(
  "connection",
  (
    socket
  ) => {

    console.log(
      `Socket connected: ${socket.userId}`
    );


    socket.join(
      `user:${socket.userId}`
    );


    socket.on(
      "disconnect",
      () => {

        console.log(
          `Socket disconnected: ${socket.userId}`
        );

      }
    );
  }
);


// ======================================================
// Redis Progress Subscriber
// ======================================================

await progressSubscriber.subscribe(
  "webshield:scan-progress"
);


progressSubscriber.on(
  "message",
  async (
    channel,
    message
  ) => {

    if (
      channel !==
      "webshield:scan-progress"
    ) {
      return;
    }


    try {

      const event =
        JSON.parse(
          message
        );


      if (
        !event.owner
      ) {
        return;
      }


      await cache.del(
        `scans:${event.owner}`
      );


      io
        .to(
          `user:${event.owner}`
        )
        .emit(
          "scan:progress",
          event
        );

    } catch (
      error
    ) {

      console.error(
        "Progress event error:",
        error.message
      );

    }
  }
);


// ======================================================
// Health
// ======================================================

app.get(
  "/api/health",

  (
    req,
    res
  ) => {

    res.json({
      ok:
        true,

      application:
        "WebShield",

      timestamp:
        new Date(),
    });
  }
);


// ======================================================
// Register
// ======================================================

app.post(
  "/api/auth/register",

  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        email,
        password,
      } =
        credentials.parse(
          req.body
        );


      const existing =
        await User.findOne({
          email,
        });


      if (
        existing
      ) {

        return res
          .status(409)
          .json({
            error:
              "Account already exists",
          });
      }


      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const user =
        await User.create({
          email,
          passwordHash,
        });


      const token =
        issueToken(
          user
        );


      setAuthCookie(
        res,
        token
      );


      res
        .status(201)
        .json({
          id:
            user._id,

          email:
            user.email,

          role:
            user.role,
        });

    } catch (
      error
    ) {

      next(
        error
      );
    }
  }
);


// ======================================================
// Login
// ======================================================

app.post(
  "/api/auth/login",

  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        email,
        password,
      } =
        credentials.parse(
          req.body
        );


      const user =
        await User.findOne({
          email,
        });


      if (
        !user ||
        !user.passwordHash
      ) {

        return res
          .status(401)
          .json({
            error:
              "Invalid email or password",
          });
      }


      const valid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );


      if (!valid) {

        return res
          .status(401)
          .json({
            error:
              "Invalid email or password",
          });
      }


      const token =
        issueToken(
          user
        );


      setAuthCookie(
        res,
        token
      );


      res.json({
        id:
          user._id,

        email:
          user.email,

        role:
          user.role,
      });

    } catch (
      error
    ) {

      next(
        error
      );
    }
  }
);


// ======================================================
// Logout
// ======================================================

app.post(
  "/api/auth/logout",

  (
    req,
    res
  ) => {

    res.clearCookie(
      "ws_token",
      {
        path:
          "/",

        httpOnly:
          true,

        sameSite:
          "strict",

        secure:
          process.env
            .NODE_ENV ===
          "production",
      }
    );


    res.json({
      ok:
        true,
    });
  }
);


// ======================================================
// Current User
// ======================================================

app.get(
  "/api/me",

  auth,

  async (
    req,
    res
  ) => {

    const user =
      await User
        .findById(
          req.user
        )
        .select(
          "name email role"
        );


    if (!user) {

      return res
        .status(404)
        .json({
          error:
            "User not found",
        });
    }


    res.json(
      user
    );
  }
);


// ======================================================
// Google OAuth
// ======================================================

const googleEnabled =
  Boolean(
    process.env
      .GOOGLE_CLIENT_ID &&
    process.env
      .GOOGLE_CLIENT_SECRET
  );


if (
  googleEnabled
) {

  passport.use(
    new GoogleStrategy(
      {
        clientID:
          process.env
            .GOOGLE_CLIENT_ID,

        clientSecret:
          process.env
            .GOOGLE_CLIENT_SECRET,

        callbackURL:
          `${PUBLIC_URL}/api/auth/google/callback`,
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {

        try {

          const email =
            profile.emails?.[0]
              ?.value
              ?.toLowerCase();


          if (!email) {

            return done(
              new Error(
                "Google account has no email"
              )
            );
          }


          let user =
            await User.findOne({
              googleId:
                profile.id,
            });


          if (!user) {

            const existing =
              await User.findOne({
                email,
              });


            if (
              existing
            ) {

              existing.googleId =
                profile.id;


              if (
                !existing.name
              ) {

                existing.name =
                  profile
                    .displayName ||
                  "";
              }


              await existing.save();

              user =
                existing;

            } else {

              user =
                await User.create({
                  name:
                    profile
                      .displayName ||
                    "",

                  email,

                  googleId:
                    profile.id,
                });
            }
          }


          done(
            null,
            user
          );

        } catch (
          error
        ) {

          done(
            error
          );
        }
      }
    )
  );


  app.get(
    "/api/auth/google",

    passport.authenticate(
      "google",
      {
        scope: [
          "profile",
          "email",
        ],

        session:
          false,
      }
    )
  );


  app.get(
    "/api/auth/google/callback",

    passport.authenticate(
      "google",
      {
        session:
          false,

        failureRedirect:
          "/?google=failed",
      }
    ),

    (
      req,
      res
    ) => {

      const token =
        issueToken(
          req.user
        );


      setAuthCookie(
        res,
        token
      );


      res.redirect(
        "/"
      );
    }
  );

} else {

  app.get(
    "/api/auth/google",

    (
      req,
      res
    ) => {

      res
        .status(503)
        .json({
          error:
            "Google OAuth is not configured",
        });
    }
  );
}


// ======================================================
// Scan History
// ======================================================

app.get(
  "/api/scans",

  auth,

  async (
    req,
    res,
    next
  ) => {

    try {

      const cacheKey =
        `scans:${req.user}`;


      const cached =
        await cache.get(
          cacheKey
        );


      if (
        cached
      ) {

        return res.json(
          JSON.parse(
            cached
          )
        );
      }


      const scans =
        await Scan
          .find({
            owner:
              req.user,
          })
          .sort({
            createdAt:
              -1,
          })
          .limit(
            50
          )
          .lean();


      await cache.set(
        cacheKey,

        JSON.stringify(
          scans
        ),

        "EX",
        5
      );


      res.json(
        scans
      );

    } catch (
      error
    ) {

      next(
        error
      );
    }
  }
);


// ======================================================
// Start Scan
// ======================================================

app.post(
  "/api/scans",

  auth,

  async (
    req,
    res
  ) => {

    try {

      if (
        req.body
          .authorized !==
        true
      ) {

        return res
          .status(400)
          .json({
            error:
              "You must confirm authorization to test this target",
          });
      }


      const url =
        validateLabUrl(
          req.body.url
        );


      const scan =
        await Scan.create({
          owner:
            req.user,

          url,

          status:
            "queued",

          scanType:
            "full",

          progress: {
            percent:
              0,

            stage:
              "Queued",

            message:
              "Waiting for scanner worker",
          },
        });


      await cache.del(
        `scans:${req.user}`
      );


      await scanQueue.add(
        "scan",

        {
          id:
            String(
              scan._id
            ),
        },

        {
          jobId:
            String(
              scan._id
            ),

          attempts:
            1,

          removeOnComplete:
            100,

          removeOnFail:
            100,
        }
      );


      res
        .status(202)
        .json({
          id:
            scan._id,

          status:
            "queued",
        });

    } catch (
      error
    ) {

      res
        .status(400)
        .json({
          error:
            error.message,
        });
    }
  }
);


// ======================================================
// Individual Scan
// ======================================================

app.get(
  "/api/scans/:id",

  auth,

  async (
    req,
    res
  ) => {

    const scan =
      await Scan.findOne({
        _id:
          req.params.id,

        owner:
          req.user,
      });


    if (!scan) {

      return res
        .status(404)
        .json({
          error:
            "Scan not found",
        });
    }


    res.json(
      scan
    );
  }
);


// ======================================================
// PDF Report
// ======================================================

app.get(
  "/api/scans/:id/report",

  auth,

  async (
    req,
    res
  ) => {

    const scan =
      await Scan.findOne({
        _id:
          req.params.id,

        owner:
          req.user,
      });


    if (!scan) {

      return res
        .status(404)
        .json({
          error:
            "Scan not found",
        });
    }


    res.type(
      "application/pdf"
    );


    res.setHeader(
      "Content-Disposition",

      `attachment; filename="webshield-report-${scan._id}.pdf"`
    );


    const pdf =
      new PDFDocument({
        margin:
          50,
      });


    pdf.pipe(
      res
    );


    pdf
      .fontSize(22)
      .text(
        "WebShield Security Assessment"
      );


    pdf.moveDown();


    pdf
      .fontSize(10)
      .text(
        `Target: ${scan.url}`
      )
      .text(
        `Status: ${scan.status}`
      )
      .text(
        `Security Score: ${scan.securityScore ?? 100}/100`
      )
      .text(
        `Pages Discovered: ${scan.pages?.length || 0}`
      )
      .text(
        `Forms Discovered: ${scan.discovery?.forms?.length || 0}`
      )
      .text(
        `API Requests: ${scan.discovery?.apiRequests?.length || 0}`
      )
      .text(
        `Total Findings: ${scan.findings?.length || 0}`
      );


    pdf.moveDown();


    pdf
      .fontSize(16)
      .text(
        "Security Findings"
      );


    if (
      !scan.findings?.length
    ) {

      pdf
        .moveDown()
        .fontSize(10)
        .text(
          "No findings detected."
        );
    }


    for (
      const finding of
      scan.findings ||
      []
    ) {

      pdf.moveDown();


      pdf
        .fontSize(12)
        .text(
          `${finding.title} - ${finding.severity}`
        );


      pdf
        .fontSize(9)
        .text(
          `OWASP: ${finding.owasp || "N/A"}`
        )
        .text(
          `Confidence: ${finding.confidence || "N/A"}`
        )
        .text(
          `URL: ${finding.url || scan.url}`
        )
        .text(
          `Evidence: ${finding.evidence || "N/A"}`
        )
        .text(
          `Remediation: ${finding.remediation || "N/A"}`
        );
    }


    pdf.end();
  }
);


// ======================================================
// API 404
// ======================================================

app.use(
  "/api",

  (
    req,
    res
  ) => {

    res
      .status(404)
      .json({
        error:
          "API endpoint not found",
      });
  }
);


// ======================================================
// Error Handler
// ======================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "API Error:",
      error
    );


    if (
      error.name ===
      "ZodError"
    ) {

      return res
        .status(400)
        .json({
          error:
            "Invalid input",
        });
    }


    res
      .status(500)
      .json({
        error:
          "Request failed",
      });
  }
);


// ======================================================
// Start Server
// ======================================================

async function startServer() {

  try {

    await connectDb();


    console.log(
      "MongoDB connected"
    );


    server.listen(
      PORT,
      "0.0.0.0",

      () => {

        console.log(
          `WebShield API + Socket.IO ready on port ${PORT}`
        );

      }
    );

  } catch (
    error
  ) {

    console.error(
      "Server startup failed:",
      error
    );


    process.exit(
      1
    );
  }
}


await startServer();