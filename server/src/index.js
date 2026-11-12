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

import IORedis from "ioredis";

import {
  Server as SocketIOServer,
} from "socket.io";

import {
  Queue,
} from "bullmq";

import {
  connectDb,
  User,
  Scan,
} from "./db.js";

import {
  validateLabUrl,
} from "./security.js";

import {
  generateProfessionalReport,
} from "./report.js";


// ======================================================
// Configuration
// ======================================================

const PORT =
  Number(
    process.env.PORT ||
    5000
  );


const REDIS_URL =
  process.env.REDIS_URL ||
  "redis://redis:6379";


const JWT_SECRET =
  process.env.JWT_SECRET;


const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID;


const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET;


const PUBLIC_URL =
  process.env.PUBLIC_URL ||
  "http://localhost:8081";


const JWT_ISSUER =
  "webshield";


const SCAN_PROGRESS_CHANNEL =
  "webshield:scan-progress";


if (
  !JWT_SECRET
) {
  throw new Error(
    "JWT_SECRET is required"
  );
}


// ======================================================
// Express / HTTP / Socket.IO
// ======================================================

const app =
  express();


const server =
  http.createServer(
    app
  );


const io =
  new SocketIOServer(
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
// Redis / BullMQ
// ======================================================

const cacheRedis =
  new IORedis(
    REDIS_URL
  );


const progressSubscriber =
  new IORedis(
    REDIS_URL
  );


const queueConnection =
  new IORedis(
    REDIS_URL,
    {
      maxRetriesPerRequest:
        null,
    }
  );


const scanQueue =
  new Queue(
    "scans",
    {
      connection:
        queueConnection,
    }
  );


// ======================================================
// Express Middleware
// ======================================================

app.disable(
  "x-powered-by"
);


app.use(
  helmet({
    contentSecurityPolicy:
      false,
  })
);


app.use(
  express.json({
    limit:
      "1mb",
  })
);


app.use(
  express.urlencoded({
    extended:
      false,
  })
);


app.use(
  cookieParser()
);


app.use(
  passport.initialize()
);


// ======================================================
// Authentication Rate Limit
// ======================================================

const authLimiter =
  rateLimit({
    windowMs:
      15 *
      60 *
      1000,

    max:
      100,

    standardHeaders:
      true,

    legacyHeaders:
      false,

    message: {
      error:
        "Too many authentication requests. Please try again later.",
    },
  });


app.use(
  "/api/auth",
  authLimiter
);


// ======================================================
// Origin Protection
// ======================================================

const publicOrigin =
  new URL(
    PUBLIC_URL
  ).origin;


app.use(
  "/api",

  (
    req,
    res,
    next
  ) => {

    if (
      [
        "GET",
        "HEAD",
        "OPTIONS",
      ].includes(
        req.method
      )
    ) {
      return next();
    }


    const origin =
      req.get(
        "origin"
      );


    if (
      origin &&
      origin !==
        publicOrigin
    ) {
      return res
        .status(403)
        .json({
          error:
            "Invalid request origin",
        });
    }


    next();
  }
);


// ======================================================
// JWT
// ======================================================

function createToken(
  user
) {
  return jwt.sign(
    {
      email:
        user.email,

      role:
        user.role,
    },

    JWT_SECRET,

    {
      subject:
        user._id.toString(),

      issuer:
        JWT_ISSUER,

      expiresIn:
        "7d",
    }
  );
}


function setAuthCookie(
  res,
  token
) {
  res.cookie(
    "ws_token",
    token,
    {
      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        PUBLIC_URL.startsWith(
          "https://"
        ),

      maxAge:
        7 *
        24 *
        60 *
        60 *
        1000,

      path:
        "/",
    }
  );
}


function clearAuthCookie(
  res
) {
  res.clearCookie(
    "ws_token",
    {
      httpOnly:
        true,

      sameSite:
        "lax",

      secure:
        PUBLIC_URL.startsWith(
          "https://"
        ),

      path:
        "/",
    }
  );
}


// ======================================================
// Auth Middleware
// ======================================================

async function requireAuth(
  req,
  res,
  next
) {
  try {

    const token =
      req.cookies
        ?.ws_token;


    if (!token) {
      return res
        .status(401)
        .json({
          error:
            "Authentication required",
        });
    }


    const payload =
      jwt.verify(
        token,
        JWT_SECRET,
        {
          issuer:
            JWT_ISSUER,
        }
      );


    const user =
      await User.findById(
        payload.sub
      );


    if (!user) {

      clearAuthCookie(
        res
      );


      return res
        .status(401)
        .json({
          error:
            "User account not found",
        });
    }


    req.user =
      user;


    next();

  } catch {

    clearAuthCookie(
      res
    );


    return res
      .status(401)
      .json({
        error:
          "Invalid or expired session",
      });
  }
}


// ======================================================
// Google OAuth
// ======================================================

if (
  GOOGLE_CLIENT_ID &&
  GOOGLE_CLIENT_SECRET
) {
  passport.use(
    new GoogleStrategy(
      {
        clientID:
          GOOGLE_CLIENT_ID,

        clientSecret:
          GOOGLE_CLIENT_SECRET,

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
            profile.emails
              ?.find(
                (
                  item
                ) =>
                  item.verified !==
                  false
              )
              ?.value
              ?.toLowerCase()
              ?.trim() ||
            profile.emails
              ?.[0]
              ?.value
              ?.toLowerCase()
              ?.trim();


          if (!email) {
            return done(
              new Error(
                "Google account does not provide an email address"
              )
            );
          }


          let user =
            await User.findOne({
              googleId:
                profile.id,
            });


          if (!user) {
            user =
              await User.findOne({
                email,
              });
          }


          if (user) {

            if (
              !user.googleId
            ) {
              user.googleId =
                profile.id;
            }


            if (
              !user.name &&
              profile.displayName
            ) {
              user.name =
                profile.displayName;
            }


            await user.save();

          } else {

            user =
              await User.create({
                name:
                  profile.displayName ||
                  "",

                email,

                googleId:
                  profile.id,

                role:
                  "user",
              });
          }


          return done(
            null,
            user
          );

        } catch (
          error
        ) {

          return done(
            error
          );

        }
      }
    )
  );
}


// ======================================================
// Socket Cookie Parser
// ======================================================

function parseCookies(
  cookieHeader = ""
) {
  const cookies =
    {};


  for (
    const part
    of cookieHeader.split(
      ";"
    )
  ) {

    const separator =
      part.indexOf(
        "="
      );


    if (
      separator ===
      -1
    ) {
      continue;
    }


    const key =
      part
        .slice(
          0,
          separator
        )
        .trim();


    const value =
      part
        .slice(
          separator +
            1
        )
        .trim();


    if (!key) {
      continue;
    }


    try {

      cookies[
        key
      ] =
        decodeURIComponent(
          value
        );

    } catch {

      cookies[
        key
      ] =
        value;

    }
  }


  return cookies;
}


// ======================================================
// Socket Authentication
// ======================================================

io.use(
  async (
    socket,
    next
  ) => {

    try {

      const cookies =
        parseCookies(
          socket
            .handshake
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
          JWT_SECRET,
          {
            issuer:
              JWT_ISSUER,
          }
        );


      const user =
        await User.findById(
          payload.sub
        );


      if (!user) {
        return next(
          new Error(
            "User not found"
          )
        );
      }


      socket.user =
        user;


      next();

    } catch {

      next(
        new Error(
          "Invalid session"
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

    const userId =
      socket
        .user
        ._id
        .toString();


    socket.join(
      `user:${userId}`
    );


    console.log(
      `Socket connected: ${userId}`
    );


    socket.on(
      "disconnect",

      () => {

        console.log(
          `Socket disconnected: ${userId}`
        );

      }
    );
  }
);


// ======================================================
// Redis Scan Progress
// ======================================================

await progressSubscriber.subscribe(
  SCAN_PROGRESS_CHANNEL
);


progressSubscriber.on(
  "message",

  async (
    channel,
    message
  ) => {

    if (
      channel !==
      SCAN_PROGRESS_CHANNEL
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


      await cacheRedis.del(
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
        "Progress subscriber error:",
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

      service:
        "API",

      timestamp:
        new Date()
          .toISOString(),
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

      const email =
        String(
          req.body.email ||
          ""
        )
          .trim()
          .toLowerCase();


      const password =
        String(
          req.body.password ||
          ""
        );


      if (
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              "Email and password are required",
          });
      }


      if (
        password.length <
        8
      ) {
        return res
          .status(400)
          .json({
            error:
              "Password must be at least 8 characters",
          });
      }


      const existing =
        await User.findOne({
          email,
        });


      if (existing) {
        return res
          .status(409)
          .json({
            error:
              "An account with this email already exists",
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

          role:
            "user",
        });


      const token =
        createToken(
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

      const email =
        String(
          req.body.email ||
          ""
        )
          .trim()
          .toLowerCase();


      const password =
        String(
          req.body.password ||
          ""
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
        createToken(
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

    clearAuthCookie(
      res
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

  requireAuth,

  (
    req,
    res
  ) => {

    res.json({
      id:
        req.user._id,

      name:
        req.user.name,

      email:
        req.user.email,

      role:
        req.user.role,
    });
  }
);


// ======================================================
// Google Login
//
// IMPORTANT:
// prompt: "select_account"
// forces Google account chooser every time.
// ======================================================

app.get(
  "/api/auth/google",

  (
    req,
    res,
    next
  ) => {

    if (
      !GOOGLE_CLIENT_ID ||
      !GOOGLE_CLIENT_SECRET
    ) {
      return res
        .status(503)
        .json({
          error:
            "Google OAuth is not configured",
        });
    }


    passport.authenticate(
      "google",

      {
        scope: [
          "profile",
          "email",
        ],

        session:
          false,

        prompt:
          "select_account",
      }
    )(
      req,
      res,
      next
    );
  }
);


// ======================================================
// Google Callback
// ======================================================

app.get(
  "/api/auth/google/callback",

  (
    req,
    res,
    next
  ) => {

    if (
      !GOOGLE_CLIENT_ID ||
      !GOOGLE_CLIENT_SECRET
    ) {
      return res.redirect(
        `${PUBLIC_URL}/?auth=google-not-configured`
      );
    }


    passport.authenticate(
      "google",

      {
        session:
          false,

        failureRedirect:
          `${PUBLIC_URL}/?auth=google-failed`,
      },

      (
        error,
        user
      ) => {

        if (
          error ||
          !user
        ) {

          console.error(
            "Google OAuth error:",
            error?.message ||
            "No user"
          );


          return res.redirect(
            `${PUBLIC_URL}/?auth=google-failed`
          );
        }


        const token =
          createToken(
            user
          );


        setAuthCookie(
          res,
          token
        );


        return res.redirect(
          PUBLIC_URL
        );
      }
    )(
      req,
      res,
      next
    );
  }
);


// ======================================================
// Scan Cache
// ======================================================

async function clearUserScanCache(
  userId
) {
  await cacheRedis.del(
    `scans:${userId}`
  );
}


// ======================================================
// Scan History
// ======================================================

app.get(
  "/api/scans",

  requireAuth,

  async (
    req,
    res,
    next
  ) => {

    try {

      const owner =
        req.user
          ._id
          .toString();


      const cacheKey =
        `scans:${owner}`;


      const cached =
        await cacheRedis.get(
          cacheKey
        );


      if (cached) {
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
              req.user._id,
          })
          .sort({
            createdAt:
              -1,
          })
          .lean();


      await cacheRedis.set(
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
// Create Scan
// ======================================================

app.post(
  "/api/scans",

  requireAuth,

  async (
    req,
    res,
    next
  ) => {

    try {

      if (
        req.body.authorized !==
        true
      ) {
        return res
          .status(400)
          .json({
            error:
              "You must confirm authorization before starting a scan",
          });
      }


      const target =
        validateLabUrl(
          String(
            req.body.url ||
            ""
          )
        );


      const scan =
        await Scan.create({
          owner:
            req.user._id,

          url:
            target,

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

          pages:
            [],

          discovery: {
            forms:
              [],

            apiRequests:
              [],
          },

          findings:
            [],

          securityScore:
            100,
        });


      await scanQueue.add(
        "security-scan",

        {
          scanId:
            scan._id.toString(),
        },

        {
          jobId:
            scan._id.toString(),

          removeOnComplete: {
            count:
              100,
          },

          removeOnFail: {
            count:
              100,
          },
        }
      );


      await clearUserScanCache(
        req.user
          ._id
          .toString()
      );


      res
        .status(202)
        .json({
          id:
            scan._id,

          status:
            scan.status,
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
// Get Individual Scan
// ======================================================

app.get(
  "/api/scans/:id",

  requireAuth,

  async (
    req,
    res,
    next
  ) => {

    try {

      const scan =
        await Scan.findOne({
          _id:
            req.params.id,

          owner:
            req.user._id,
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
// Professional PDF Report
// ======================================================

app.get(
  "/api/scans/:id/report",

  requireAuth,

  async (
    req,
    res,
    next
  ) => {

    try {

      const scan =
        await Scan.findOne({
          _id:
            req.params.id,

          owner:
            req.user._id,
        });


      if (!scan) {
        return res
          .status(404)
          .json({
            error:
              "Scan not found",
          });
      }


      if (
        scan.status !==
        "completed"
      ) {
        return res
          .status(409)
          .json({
            error:
              "PDF report is available only after the scan is completed",
          });
      }


      generateProfessionalReport(
        scan,
        req.user,
        res
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
// Global Error Handler
// ======================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "API error:",
      error
    );


    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }


    if (
      error?.name ===
      "CastError"
    ) {
      return res
        .status(400)
        .json({
          error:
            "Invalid identifier",
        });
    }


    if (
      error?.code ===
      11000
    ) {
      return res
        .status(409)
        .json({
          error:
            "Duplicate record",
        });
    }


    res
      .status(500)
      .json({
        error:
          error?.message ||
          "Internal server error",
      });
  }
);


// ======================================================
// Start API
// ======================================================

await connectDb();


server.listen(
  PORT,
  "0.0.0.0",

  () => {

    console.log(
      `WebShield API + Socket.IO ready on port ${PORT}`
    );

  }
);