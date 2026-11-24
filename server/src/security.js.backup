
import jwt from "jsonwebtoken";
import { z } from "zod";

export const credentials = z.object({
  email: z.string().email().max(200),
  password: z.string().min(8).max(128),
});

// ======================================================
// JWT
// ======================================================

export function issueToken(user) {
  return jwt.sign(
    {
      sub: String(user._id),
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "2h",
      issuer: "webshield",
    }
  );
}

// ======================================================
// Authentication Cookie
// ======================================================

export function setAuthCookie(res, token) {
  res.cookie("ws_token", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7200000,
    path: "/",
  });
}

// ======================================================
// Authentication Middleware
// ======================================================

export function auth(req, res, next) {
  try {
    const token = req.cookies.ws_token;

    const claims = jwt.verify(
      token,
      process.env.JWT_SECRET,
      {
        issuer: "webshield",
      }
    );

    req.user = claims.sub;

    next();

  } catch {
    res.status(401).json({
      error: "Authentication required",
    });
  }
}

// ======================================================
// URL Validation Error
// ======================================================

function targetError(statusCode, message) {
  const error = new Error(message);

  error.statusCode = statusCode;

  return error;
}

// ======================================================
// Secure Lab URL Validation
// ======================================================

export function validateLabUrl(raw) {
  let url;

  try {
    url = new URL(raw);
  } catch {
    throw targetError(
      400,
      "A valid target URL is required"
    );
  }

  const allowedHosts = (
    process.env.SCAN_ALLOWED_HOSTS || "lab"
  )
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);

  const protocolAllowed = [
    "http:",
    "https:",
  ].includes(url.protocol);

  const credentialsPresent = Boolean(
    url.username || url.password
  );

  const portAllowed =
    !url.port ||
    ["4000", "80", "443"].includes(url.port);

  const hostAllowed = allowedHosts.includes(
    url.hostname.toLowerCase()
  );

  if (
    !protocolAllowed ||
    credentialsPresent ||
    !portAllowed ||
    !hostAllowed
  ) {
    throw targetError(
      403,
      "Only explicitly allowlisted lab targets are supported"
    );
  }

  url.hash = "";

  return url.toString();
}
