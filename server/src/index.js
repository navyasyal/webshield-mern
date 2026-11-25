
import express from "express";
import http from "node:http";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import passport from "passport";
import swaggerUi from "swagger-ui-express";
import swaggerJsdoc from "swagger-jsdoc";

import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import IORedis from "ioredis";
import { Server as SocketIOServer } from "socket.io";
import { Queue } from "bullmq";

import {
  connectDb,
  User,
  Scan,
} from "./db.js";

import { validateLabUrl } from "./security.js";
import { generateProfessionalReport } from "./report.js";

// ======================================================
// Configuration
// ======================================================

const PORT = Number(process.env.PORT || 5000);
const REDIS_URL = process.env.REDIS_URL || "redis://redis:6379";
const JWT_SECRET = process.env.JWT_SECRET;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const PUBLIC_URL =
  process.env.PUBLIC_URL || "http://localhost:8081";

const API_URL =
  process.env.API_URL ||
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${PORT}`;

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || ""
).trim().toLowerCase();

const JWT_ISSUER = "webshield";
const SCAN_PROGRESS_CHANNEL = "webshield:scan-progress";

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

const publicOrigin = new URL(PUBLIC_URL).origin;
const apiOrigin = new URL(API_URL).origin;

// ======================================================
// Express / HTTP / Socket.IO
// ======================================================

const app = express();

app.set("trust proxy", 1);

const server = http.createServer(app);

const io = new SocketIOServer(server, {
  path: "/socket.io",
  cors: {
    origin: publicOrigin,
    credentials: true,
  },
});

// ======================================================
// Redis / BullMQ
// ======================================================

const cacheRedis = new IORedis(REDIS_URL);
const progressSubscriber = new IORedis(REDIS_URL);

const queueConnection = new IORedis(REDIS_URL, {
  maxRetriesPerRequest: null,
});

const scanQueue = new Queue("scans", {
  connection: queueConnection,
});

// ======================================================
// Express Middleware
// ======================================================

app.disable("x-powered-by");

app.use(
  cors({
    origin: publicOrigin,
    credentials: true,
  })
);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(passport.initialize());

// ======================================================
// Swagger API Documentation
// ======================================================

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.3",

    info: {
      title: "WebShield API",
      version: "1.0.0",
      description:
        "API documentation for WebShield - MERN-based web security scanner with authentication and RBAC.",
    },

    servers: [
      {
        url: API_URL,
        description: "API server",
      },
      {
        url: "http://localhost:5000",
        description: "Local development server",
      },
    ],

    tags: [
      { name: "Health", description: "API health checks" },
      { name: "Authentication", description: "User authentication" },
      { name: "Scans", description: "Security scanning operations" },
      { name: "Admin", description: "Administrator-only operations" },
    ],

    components: {
      securitySchemes: {
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "ws_token",
          description: "HTTP-only authentication cookie",
        },
      },

      schemas: {
        Error: {
          type: "object",
          properties: {
            error: {
              type: "string",
              example: "Authentication required",
            },
          },
        },

        ScanRequest: {
          type: "object",
          required: ["url", "authorized"],
          properties: {
            url: {
              type: "string",
              example: "https://webshield-mern.onrender.com/",
            },
            authorized: {
              type: "boolean",
              example: true,
            },
          },
        },

        RoleUpdate: {
          type: "object",
          required: ["role"],
          properties: {
            role: {
              type: "string",
              enum: ["user", "admin"],
              example: "admin",
            },
          },
        },
      },
    },

    paths: {
      "/api/health": {
        get: {
          tags: ["Health"],
          summary: "Check API health",
          responses: {
            200: { description: "API is running" },
          },
        },
      },

      "/api/auth/register": {
        post: {
          tags: ["Authentication"],
          summary: "Register a new user",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email", "password"],
                  properties: {
                    email: {
                      type: "string",
                      example: "user@example.com",
                    },
                    password: {
                      type: "string",
                      example: "Password123",
                    },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: "User registered successfully" },
            400: { description: "Invalid registration details" },
            409: { description: "Account already exists" },
          },
        },
      },

      "/api/auth/login": {
        post: {
          tags: ["Authentication"],
          summary: "Login user",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["email", "password"],
                  properties: {
                    email: {
                      type: "string",
                      example: "user@example.com",
                    },
                    password: {
                      type: "string",
                      example: "Password123",
                    },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: "Login successful" },
            401: { description: "Invalid credentials" },
          },
        },
      },

      "/api/auth/logout": {
        post: {
          tags: ["Authentication"],
          summary: "Logout user",
          responses: {
            200: { description: "Logout successful" },
          },
        },
      },

      "/api/me": {
        get: {
          tags: ["Authentication"],
          summary: "Get current authenticated user",
          security: [{ cookieAuth: [] }],
          responses: {
            200: { description: "Current user details" },
            401: { description: "Authentication required" },
          },
        },
      },

      "/api/auth/google": {
        get: {
          tags: ["Authentication"],
          summary: "Start Google OAuth login",
          responses: {
            302: { description: "Redirect to Google authentication" },
            503: { description: "Google OAuth is not configured" },
          },
        },
      },

      "/api/auth/google/callback": {
        get: {
          tags: ["Authentication"],
          summary: "Google OAuth callback",
          responses: {
            302: { description: "Redirect after authentication" },
          },
        },
      },

      "/api/scans": {
        get: {
          tags: ["Scans"],
          summary: "Get scan history of logged-in user",
          security: [{ cookieAuth: [] }],
          responses: {
            200: { description: "List of user scans" },
            401: { description: "Authentication required" },
          },
        },

        post: {
          tags: ["Scans"],
          summary: "Start a new security scan",
          security: [{ cookieAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  $ref: "#/components/schemas/ScanRequest",
                },
              },
            },
          },
          responses: {
            202: { description: "Scan successfully queued" },
            400: { description: "Invalid target or authorization missing" },
            401: { description: "Authentication required" },
          },
        },
      },

      "/api/scans/{id}": {
        get: {
          tags: ["Scans"],
          summary: "Get details of an individual scan",
          security: [{ cookieAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          responses: {
            200: { description: "Scan details" },
            404: { description: "Scan not found" },
          },
        },
      },

      "/api/scans/{id}/report": {
        get: {
          tags: ["Scans"],
          summary: "Download professional PDF scan report",
          security: [{ cookieAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: {
                type: "string",
                format: "binary",
              },
            },
          ],
          responses: {
            200: {
              description: "PDF report",
              content: {
                "application/pdf": {
                  schema: {
                    type: "string",
                    format: "binary",
                  },
                },
              },
            },
            404: { description: "Scan not found" },
            409: { description: "Scan is not completed yet" },
          },
        },
      },

      "/api/admin/users": {
        get: {
          tags: ["Admin"],
          summary: "Get all registered users",
          description: "Admin role required.",
          security: [{ cookieAuth: [] }],
          responses: {
            200: { description: "Users retrieved successfully" },
            401: { description: "Authentication required" },
            403: { description: "Admin access required" },
          },
        },
      },

      "/api/admin/scans": {
        get: {
          tags: ["Admin"],
          summary: "Get all scans",
          description: "Admin role required.",
          security: [{ cookieAuth: [] }],
          responses: {
            200: { description: "Scans retrieved successfully" },
            401: { description: "Authentication required" },
            403: { description: "Admin access required" },
          },
        },
      },

      "/api/admin/users/{id}/role": {
        patch: {
          tags: ["Admin"],
          summary: "Update a user's role",
          description:
            "Admin role required. An admin cannot change their own role.",
          security: [{ cookieAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  $ref: "#/components/schemas/RoleUpdate",
                },
              },
            },
          },
          responses: {
            200: { description: "Role updated successfully" },
            400: { description: "Invalid role or user ID" },
            401: { description: "Authentication required" },
            403: { description: "Admin access required" },
            404: { description: "User not found" },
          },
        },
      },
    },
  },

  apis: [],
});

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    swaggerOptions: {
      withCredentials: true,
    },
  })
);

// ======================================================
// Authentication Rate Limit
// ======================================================

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication requests. Please try again later.",
  },
});

app.use("/api/auth", authLimiter);

// ======================================================
// Origin Protection - FIXED
// ======================================================

// Allow the official frontend and this API's own origin.
// Swagger is served from the API domain itself.

const trustedOrigins = new Set([
  publicOrigin,
  apiOrigin,
]);

app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const origin = req.get("origin");

  if (origin && !trustedOrigins.has(origin)) {
    return res.status(403).json({
      error: "Invalid request origin",
    });
  }

  next();
});

// ======================================================
// JWT
// ======================================================

function createToken(user) {
  return jwt.sign(
    {
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    {
      subject: user._id.toString(),
      issuer: JWT_ISSUER,
      expiresIn: "7d",
    }
  );
}

function setAuthCookie(res, token) {
  res.cookie("ws_token", token, {
    httpOnly: true,
    sameSite: PUBLIC_URL.startsWith("https://") ? "none" : "lax",
    secure: PUBLIC_URL.startsWith("https://"),
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });
}

function clearAuthCookie(res) {
  res.clearCookie("ws_token", {
    httpOnly: true,
    sameSite: PUBLIC_URL.startsWith("https://") ? "none" : "lax",
    secure: PUBLIC_URL.startsWith("https://"),
    path: "/",
  });
}

// ======================================================
// Authentication Middleware
// ======================================================

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.ws_token;

    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
    });

    const user = await User.findById(payload.sub);

    if (!user) {
      clearAuthCookie(res);

      return res.status(401).json({
        error: "User account not found",
      });
    }

    req.user = user;
    next();
  } catch {
    clearAuthCookie(res);

    return res.status(401).json({
      error: "Invalid or expired session",
    });
  }
}

// ======================================================
// Role-Based Access Control
// ======================================================

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Access denied. Insufficient permissions.",
      });
    }

    next();
  };
}

// ======================================================
// Google OAuth
// ======================================================

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: `${API_URL}/api/auth/google/callback`,
      },

      async (accessToken, refreshToken, profile, done) => {
        try {
          const email =
            profile.emails
              ?.find((item) => item.verified !== false)
              ?.value
              ?.toLowerCase()
              ?.trim() ||
            profile.emails?.[0]?.value
              ?.toLowerCase()
              ?.trim();

          if (!email) {
            return done(
              new Error(
                "Google account does not provide an email address"
              )
            );
          }

          let user = await User.findOne({
            googleId: profile.id,
          });

          if (!user) {
            user = await User.findOne({ email });
          }

          if (user) {
            if (!user.googleId) {
              user.googleId = profile.id;
            }

            if (!user.name && profile.displayName) {
              user.name = profile.displayName;
            }

            await user.save();
          } else {
            user = await User.create({
              name: profile.displayName || "",
              email,
              googleId: profile.id,
              role: "user",
            });
          }

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

// ======================================================
// Socket Cookie Parser
// ======================================================

function parseCookies(cookieHeader = "") {
  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (!key) continue;

    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  }

  return cookies;
}

// ======================================================
// Socket Authentication
// ======================================================

io.use(async (socket, next) => {
  try {
    const cookies = parseCookies(
      socket.handshake.headers.cookie || ""
    );

    const token = cookies.ws_token;

    if (!token) {
      return next(new Error("Authentication required"));
    }

    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
    });

    const user = await User.findById(payload.sub);

    if (!user) {
      return next(new Error("User not found"));
    }

    socket.user = user;
    next();
  } catch {
    next(new Error("Invalid session"));
  }
});

// ======================================================
// Socket Connection
// ======================================================

io.on("connection", (socket) => {
  const userId = socket.user._id.toString();

  socket.join(`user:${userId}`);

  console.log(`Socket connected: ${userId}`);

  socket.on("disconnect", () => {
    console.log(`Socket disconnected: ${userId}`);
  });
});

// ======================================================
// Redis Scan Progress
// ======================================================

await progressSubscriber.subscribe(SCAN_PROGRESS_CHANNEL);

progressSubscriber.on("message", async (channel, message) => {
  if (channel !== SCAN_PROGRESS_CHANNEL) return;

  try {
    const event = JSON.parse(message);

    if (!event.owner) return;

    await cacheRedis.del(`scans:${event.owner}`);

    io
      .to(`user:${event.owner}`)
      .emit("scan:progress", event);
  } catch (error) {
    console.error(
      "Progress subscriber error:",
      error.message
    );
  }
});

// ======================================================
// Health
// ======================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    application: "WebShield",
    service: "API",
    timestamp: new Date().toISOString(),
  });
});

// ======================================================
// Register
// ======================================================

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters",
      });
    }

    const existing = await User.findOne({ email });

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      email,
      passwordHash,
      role: "user",
    });

    const token = createToken(user);
    setAuthCookie(res, token);

    res.status(201).json({
      id: user._id,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    next(error);
  }
});

// ======================================================
// Login
// ======================================================

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const user = await User.findOne({ email });

    if (!user || !user.passwordHash) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const token = createToken(user);
    setAuthCookie(res, token);

    res.json({
      id: user._id,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    next(error);
  }
});

// ======================================================
// Logout
// ======================================================

app.post("/api/auth/logout", (req, res) => {
  clearAuthCookie(res);

  res.json({
    ok: true,
  });
});

// ======================================================
// Current User
// ======================================================

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    id: req.user._id,
    name: req.user.name,
    email: req.user.email,
    role: req.user.role,
  });
});

// ======================================================
// Google Login
// ======================================================

app.get("/api/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.status(503).json({
      error: "Google OAuth is not configured",
    });
  }

  passport.authenticate(
    "google",
    {
      scope: ["profile", "email"],
      session: false,
      prompt: "select_account",
    }
  )(req, res, next);
});

// ======================================================
// Google Callback
// ======================================================

app.get("/api/auth/google/callback", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.redirect(
      `${PUBLIC_URL}/?auth=google-not-configured`
    );
  }

  passport.authenticate(
    "google",
    {
      session: false,
      failureRedirect: `${PUBLIC_URL}/?auth=google-failed`,
    },
    (error, user) => {
      if (error || !user) {
        console.error(
          "Google OAuth error:",
          error?.message || "No user"
        );

        return res.redirect(
          `${PUBLIC_URL}/?auth=google-failed`
        );
      }

      const token = createToken(user);
      setAuthCookie(res, token);

      return res.redirect(PUBLIC_URL);
    }
  )(req, res, next);
});

// ======================================================
// Scan Cache
// ======================================================

async function clearUserScanCache(userId) {
  await cacheRedis.del(`scans:${userId}`);
}

// ======================================================
// Scan History
// ======================================================

app.get(
  "/api/scans",
  requireAuth,
  async (req, res, next) => {
    try {
      const owner = req.user._id.toString();
      const cacheKey = `scans:${owner}`;

      const cached = await cacheRedis.get(cacheKey);

      if (cached) {
        return res.json(JSON.parse(cached));
      }

      const scans = await Scan.find({
        owner: req.user._id,
      })
        .sort({ createdAt: -1 })
        .lean();

      await cacheRedis.set(
        cacheKey,
        JSON.stringify(scans),
        "EX",
        5
      );

      res.json(scans);
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// Create Scan
// ======================================================

app.post(
  "/api/scans",
  requireAuth,
  async (req, res, next) => {
    try {
      if (req.body.authorized !== true) {
        return res.status(400).json({
          error:
            "You must confirm authorization before starting a scan",
        });
      }

      const target = validateLabUrl(
        String(req.body.url || "")
      );

      const scan = await Scan.create({
        owner: req.user._id,
        url: target,
        status: "queued",
        scanType: "full",

        progress: {
          percent: 0,
          stage: "Queued",
          message: "Waiting for scanner worker",
        },

        pages: [],

        discovery: {
          forms: [],
          apiRequests: [],
        },

        findings: [],

        securityScore: 100,
      });

      await scanQueue.add(
        "security-scan",
        {
          scanId: scan._id.toString(),
        },
        {
          jobId: scan._id.toString(),
          removeOnComplete: { count: 100 },
          removeOnFail: { count: 100 },
        }
      );

      await clearUserScanCache(
        req.user._id.toString()
      );

      res.status(202).json({
        id: scan._id,
        status: scan.status,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// Get Individual Scan
// ======================================================

app.get(
  "/api/scans/:id",
  requireAuth,
  async (req, res, next) => {
    try {
      const scan = await Scan.findOne({
        _id: req.params.id,
        owner: req.user._id,
      });

      if (!scan) {
        return res.status(404).json({
          error: "Scan not found",
        });
      }

      res.json(scan);
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// Professional PDF Report
// ======================================================

app.get(
  "/api/scans/:id/report",
  requireAuth,
  async (req, res, next) => {
    try {
      const scan = await Scan.findOne({
        _id: req.params.id,
        owner: req.user._id,
      });

      if (!scan) {
        return res.status(404).json({
          error: "Scan not found",
        });
      }

      if (scan.status !== "completed") {
        return res.status(409).json({
          error:
            "PDF report is available only after the scan is completed",
        });
      }

      generateProfessionalReport(
        scan,
        req.user,
        res
      );
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// ADMIN: GET ALL USERS
// ======================================================

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const users = await User.find()
        .select("name email role createdAt updatedAt")
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();

      res.json({
        total: users.length,
        users,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// ADMIN: GET ALL SCANS
// ======================================================

app.get(
  "/api/admin/scans",
  requireAuth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const scans = await Scan.find()
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();

      res.json({
        total: scans.length,
        scans,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// ADMIN: UPDATE USER ROLE
// ======================================================

app.patch(
  "/api/admin/users/:id/role",
  requireAuth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const { role } = req.body;
      const userId = req.params.id;

      if (!["user", "admin"].includes(role)) {
        return res.status(400).json({
          error: "Role must be either user or admin",
        });
      }

      if (!/^[0-9a-fA-F]{24}$/.test(userId)) {
        return res.status(400).json({
          error: "Invalid user ID",
        });
      }

      if (userId === req.user._id.toString()) {
        return res.status(400).json({
          error: "You cannot change your own role",
        });
      }

      const user = await User.findByIdAndUpdate(
        userId,
        { role },
        {
          new: true,
          runValidators: true,
        }
      ).select("name email role");

      if (!user) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      res.json({
        message: "User role updated successfully",
        user,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ======================================================
// API 404
// ======================================================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found",
  });
});

// ======================================================
// Global Error Handler
// ======================================================

app.use((error, req, res, next) => {
  console.error("API error:", error);

  if (res.headersSent) {
    return next(error);
  }

  if (error?.name === "CastError") {
    return res.status(400).json({
      error: "Invalid identifier",
    });
  }

  if (error?.code === 11000) {
    return res.status(409).json({
      error: "Duplicate record",
    });
  }

  const statusCode = Number(
    error?.statusCode || error?.status
  );

  if (
    Number.isInteger(statusCode) &&
    statusCode >= 400 &&
    statusCode < 500
  ) {
    return res.status(statusCode).json({
      error:
        error.message || "Request could not be processed",
    });
  }

  return res.status(500).json({
    error: "Internal server error",
  });
});

// ======================================================
// Start API
// ======================================================

await connectDb();

// Promote only the existing account explicitly configured
// by the deployment environment.

if (ADMIN_EMAIL) {
  const adminUser = await User.findOneAndUpdate(
    { email: ADMIN_EMAIL },
    { $set: { role: "admin" } },
    { new: true }
  );

  if (adminUser) {
    console.log(`Initial admin configured: ${ADMIN_EMAIL}`);
  } else {
    console.warn(
      `ADMIN_EMAIL account not found: ${ADMIN_EMAIL}`
    );
  }
}

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `WebShield API + Socket.IO ready on port ${PORT}`
  );
});
