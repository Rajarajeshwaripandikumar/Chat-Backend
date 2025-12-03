// src/index.js
import dotenv from "dotenv";
dotenv.config();

import path from "path";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";

import { connectDB, closeDB, isConnected, mongoHealthMiddleware } from "./lib/db.js"; // resilient db module (retries)
import authRoutes from "./routes/auth.route.js";
import messageRoutes from "./routes/message.route.js";
// IMPORTANT: lib/socket.js must export `app`, `server`, `io`, and createGracefulExit()
import { app, server, io, createGracefulExit } from "./lib/socket.js";

/**
 * DEV helper: persist unhandled rejections & exceptions to a file for easier debugging.
 * This runs only when NODE_ENV !== "production".
 */
if (process.env.NODE_ENV !== "production") {
  try {
    import("fs").then(({ appendFile }) => {
      const safeAppend = (text) => {
        try { appendFile("./dev-unhandled.log", text + "\n"); } catch (e) { /* ignore */ }
      };

      process.on("unhandledRejection", (reason, promise) => {
        const dump = {
          ts: new Date().toISOString(),
          type: "unhandledRejection",
          reason: typeof reason === "object" && reason ? (reason.stack || reason.message) : String(reason),
        };
        safeAppend(JSON.stringify(dump));
      });

      process.on("uncaughtException", (err) => {
        const dump = {
          ts: new Date().toISOString(),
          type: "uncaughtException",
          error: (err && err.stack) || String(err),
        };
        safeAppend(JSON.stringify(dump));
      });
    }).catch(() => { /* ignore import errors */ });
  } catch (e) {
    /* ignore safety wrapper errors */
  }
}

const PORT = process.env.PORT || 5000;
const __dirname = path.resolve();

// FRONTEND_ORIGINS env can be a comma-separated list: "http://localhost:5173,https://app.example.com"
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim());

// Express app safety settings
app.set("trust proxy", process.env.TRUST_PROXY === "true" || process.env.NODE_ENV === "production");

// CORS configuration for express (uses same origins list used by socket.js)
const corsOptions = {
  origin: (origin, cb) => {
    // allow requests with no origin (like mobile apps or curl)
    if (!origin) return cb(null, true);
    if (FRONTEND_ORIGINS.indexOf(origin) !== -1) {
      return cb(null, true);
    }
    cb(new Error("CORS policy: Origin not allowed"));
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

// Basic rate limiter - tune for your app
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // limit each IP to 120 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

// Middlewares
app.use(helmet());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(cookieParser());
app.use(cors(corsOptions));
app.use("/api/", apiLimiter); // apply rate limiter to API routes

// Healthcheck (useful for probes)
// Use real DB status when possible
app.get("/healthz", (req, res) =>
  res.json({
    ok: true,
    uptime: process.uptime(),
    db: isConnected() ? "connected" : "disconnected",
  })
);

// optional endpoint that returns 200/503 based on Mongo state (useful for LB/Readiness probes)
if (typeof mongoHealthMiddleware === "function") {
  app.use("/mongo-health", mongoHealthMiddleware());
}

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/messages", messageRoutes);

// Serve frontend in production (adjust path to your actual build output)
if (process.env.NODE_ENV === "production") {
  // make sure the relative path is correct for your deployment
  const staticPath = path.join(__dirname, "../frontend/dist");
  app.use(express.static(staticPath));
  app.get("*", (req, res) => {
    res.sendFile(path.join(staticPath, "index.html"));
  });
}

// 404 fallback for API routes (keep this after routes)
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// ----------------- Defensive server listening bookkeeping -----------------
// Some server implementations/adapters might not reliably expose `server.listening`
// at all times. Track when we actually started listening so closeHttpServer can decide.
if (server && typeof server.on === "function") {
  // set a small internal flag when 'listening' fires
  server.on("listening", () => {
    try { server.__wasListened = true; } catch (e) { /* ignore */ }
  });
}

// Helper that promisifies server.close()
function closeHttpServer(srv) {
  return new Promise((resolve, reject) => {
    try {
      // Defensive: if server not present or not closable, resolve
      if (!srv || typeof srv.close !== "function") return resolve();

      // If we already started shutting this server down, skip duplicate close attempts
      if (srv.__isShuttingDown) {
        return resolve();
      }

      // If server.listening is present and false, or we never observed listening, check alternative:
      // Use either the internal flag (set on 'listening') or server.address() which returns null if not bound.
      const wasListened = !!srv.__wasListened;
      const hasAddress = typeof srv.address === "function" && srv.address() !== null;
      const appearsRunning = (typeof srv.listening !== "undefined" ? !!srv.listening : wasListened || hasAddress);

      if (!appearsRunning) {
        // server not started or already closed — skip close
        return resolve();
      }

      // Mark shutting down to prevent races
      try { srv.__isShuttingDown = true; } catch (e) { /* ignore */ }

      srv.close((err) => {
        if (err) {
          // Ignore 'server not running' style errors gracefully
          if (err && (err.code === "ERR_SERVER_NOT_RUNNING" || err.code === "ERR_SERVER_ALREADY_CLOSED")) {
            return resolve();
          }
          return reject(err);
        }
        return resolve();
      });
    } catch (err) {
      // Defensive: if close threw synchronously, resolve instead of rejecting to avoid blocking shutdown
      return resolve();
    }
  });
}

/**
 * Start server immediately and connect DB in background:
 * - This keeps sockets alive if DB is temporarily unreachable.
 * - connectDB() should implement its own retry/backoff logic (see src/lib/db.js).
 */
function start() {
  // Start HTTP + Socket.IO server immediately
  if (!server.listening && !server.__wasListened) {
    server.listen(PORT, () => {
      // server 'listening' event will set __wasListened; set again just to be safe
      try { server.__wasListened = true; } catch (e) { /* ignore */ }
      console.log(`Server listening on port ${PORT}`);
    });
  } else {
    console.log("Server already listening — skipping server.listen()");
  }

  // Connect DB in background. connectDB should retry; we log errors but do not exit process here.
  (async () => {
    try {
      await connectDB(); // connectDB will retry internally if implemented that way
      console.log("MongoDB connected successfully (background).");
    } catch (err) {
      // Log but DON'T exit — server remains up and will continue to serve non-DB features.
      console.error("MongoDB connection failed (background):", err);
      console.warn("Continuing to run without DB. Socket.IO and HTTP remain active.");
    }
  })();
}

start();

// Create a graceful socket closer (do not auto-register signals here)
const gracefulFromSocket = createGracefulExit({
  onCloseComplete: () => {
    console.log("[index] socket layer closed (createGracefulExit callback).");
  },
});

// ---------------------- Enhanced shutdown + diagnostics ----------------------
(async () => {
  // dynamic import used to avoid top-level imports if not needed elsewhere
  const os = await import("os");
  const processStartTime = Date.now();
  console.log(`[proc] pid=${process.pid} argv=${process.argv.join(" ")} node=${process.version}`);
  console.log(`[proc] platform=${os.platform()} arch=${os.arch()} cpus=${os.cpus().length}`);

  // catch server/io errors early
  if (server && typeof server.on === "function") {
    server.on("error", (err) => {
      console.error("[server] error event:", err && err.stack ? err.stack : err);
    });
  }
  if (typeof io !== "undefined" && io && typeof io.on === "function") {
    io.on("error", (err) => {
      console.error("[socket.io] error event:", err && err.stack ? err.stack : err);
    });
    try {
      // adapter errors (optional)
      io.of("/").adapter?.on?.("error", (e) => console.warn("[socket.adapter] error", e));
    } catch (e) {
      /* ignore if adapter not present */
    }
  }

  // Make shutdown idempotent: only run once
  let isShuttingDown = false;

  /**
   * more-verbose shutdown routine: logs cause & stack, tries graceful close, then optionally exits
   * @param {number} code exit code
   * @param {string} reason reason short string (SIGTERM, uncaughtException, manual, etc)
   * @param {Error|any} extra optional extra payload (error object, signal object, etc)
   */
  async function shutdownAndExit(code = 0, reason = "manual", extra = null) {
    // Immediate trace to identify caller (helpful to know who invoked shutdown)
    console.error(`[shutdown] shutdownAndExit called — reason="${reason}" code=${code}`);
    console.error("[shutdown] call stack (trace):");
    console.error(new Error("shutdown called at").stack);

    if (isShuttingDown) {
      console.warn("[shutdown] already in progress — ignoring duplicate call", reason);
      return;
    }
    isShuttingDown = true;

    try {
      console.group && console.group("shutdown");
      console.log(`\n=== Shutdown initiated ===`);
      console.log(`pid=${process.pid} reason=${reason} code=${code}`);
      console.log(`uptime_s=${(Date.now() - processStartTime) / 1000}`);
      try { console.log("mem:", process.memoryUsage()); } catch (e) { /* ignore */ }
      if (extra) {
        console.log("shutdown extra info:", extra && extra.stack ? extra.stack : extra);
      }

      const GRACE_PERIOD_MS = parseInt(process.env.SHUTDOWN_GRACE_MS || "10000", 10) || 10000;
      const FORCE_EXIT_ON_GRACE = process.env.FORCE_EXIT_ON_GRACE === "true";
      const forceTimer = setTimeout(() => {
        console.error("Force exit: grace period expired.");
        // prefer non-zero code if we were shutting down due to error
        const exitCode = code === 0 ? 1 : code;
        // In production we exit; in dev only if explicitly forced
        if (process.env.NODE_ENV === "production" || FORCE_EXIT_ON_GRACE) {
          process.exit(exitCode);
        } else {
          console.warn("[shutdown] grace expired but not exiting (dev mode).");
        }
      }, GRACE_PERIOD_MS);
      try { forceTimer.unref(); } catch (e) { /* ignore */ }

      // 1) stop accepting new HTTP connections and wait for existing
      try {
        if (server && typeof server.close === "function") {
          await closeHttpServer(server);
          console.log("HTTP server closed.");
        } else {
          console.log("No HTTP server.close() available (skipping)");
        }
      } catch (httpErr) {
        console.warn("Error while closing HTTP server:", httpErr && httpErr.stack ? httpErr.stack : httpErr);
      }

      // 2) close Socket.IO via socket layer's graceful function (await it)
      try {
        if (typeof gracefulFromSocket === "function") {
          await gracefulFromSocket();
          console.log("Socket layer closed via gracefulFromSocket().");
        } else {
          console.log("No gracefulFromSocket function available (skipping socket close).");
        }
      } catch (ioErr) {
        console.warn("Error while closing socket layer:", ioErr && ioErr.stack ? ioErr.stack : ioErr);
      }

      // 3) close DB connection last
      try {
        if (typeof closeDB === "function") {
          await closeDB();
          console.log("DB connection closed.");
        } else {
          console.log("No closeDB function exported (skipping DB close).");
        }
      } catch (dbErr) {
        console.warn("Error closing DB:", dbErr && dbErr.stack ? dbErr.stack : dbErr);
      }

      clearTimeout(forceTimer);
      console.log("Shutdown complete.");
      console.groupEnd && console.groupEnd("shutdown");
    } catch (err) {
      console.error("Fatal error during shutdown:", err && err.stack ? err.stack : err);
    } finally {
      // Only exit automatically in production, or when explicitly requested by env:
      const FORCE_EXIT_ON_ERROR = process.env.FORCE_SHUTDOWN_ON_ERROR === "true";
      if (process.env.NODE_ENV === "production" || FORCE_EXIT_ON_ERROR) {
        console.log("Exiting process (production or FORCE_SHUTDOWN_ON_ERROR=true).");
        try { process.exit(code === 0 ? 0 : code); } catch (e) { /* ignore */ }
      } else {
        // In development, don't exit automatically — keeps nodemon / debugger stable.
        console.log("[shutdown] not exiting process automatically (dev mode). Set FORCE_SHUTDOWN_ON_ERROR=true to force exit.");
      }
    }
  }

  // -- DB watchdog --
  // This periodically checks the DB health and keeps a counter of consecutive failures.
  // It will only call shutdownAndExit if FORCE_SHUTDOWN_ON_DB=true or in production and threshold exceeded.
  const DB_WATCH_INTERVAL_MS = parseInt(process.env.DB_WATCH_INTERVAL_MS || "5000", 10);
  const DB_WATCH_THRESHOLD = parseInt(process.env.DB_WATCH_THRESHOLD || "6", 10); // e.g., 6 * 5s = 30s sustained
  let dbConsecutiveDown = 0;

  const dbWatchHandle = setInterval(() => {
    try {
      if (isConnected && typeof isConnected === "function") {
        if (isConnected()) {
          if (dbConsecutiveDown > 0) {
            console.log(`[db-watch] Mongo reconnected; clearing counter (was ${dbConsecutiveDown}).`);
          }
          dbConsecutiveDown = 0;
          return;
        }
      }
      // if here, db is not connected
      dbConsecutiveDown += 1;
      console.warn(`[db-watch] Mongo not connected (consecutive=${dbConsecutiveDown}).`);
      // Only attempt automated shutdown if explicitly requested by env var OR running in production
      const shouldForceShutdown = process.env.FORCE_SHUTDOWN_ON_DB === "true" || process.env.NODE_ENV === "production";
      if (dbConsecutiveDown >= DB_WATCH_THRESHOLD) {
        console.error(`[db-watch] Mongo disconnected for ${dbConsecutiveDown} checks (threshold ${DB_WATCH_THRESHOLD}).`);
        if (shouldForceShutdown) {
          console.error("[db-watch] Initiating graceful shutdown due to sustained DB outage.");
          shutdownAndExit(1, "sustained_db_outage");
        } else {
          console.warn("[db-watch] Sustained DB outage detected but FORCE_SHUTDOWN_ON_DB not set. Manual action required.");
        }
      }
    } catch (err) {
      console.error("[db-watch] error checking db state:", err && err.stack ? err.stack : err);
    }
  }, DB_WATCH_INTERVAL_MS).unref();

  // signal handlers
  process.on("SIGINT", () => {
    console.log("Received SIGINT");
    // For manual SIGINT we usually do want to exit even in dev
    shutdownAndExit(0, "SIGINT");
  });
  process.on("SIGTERM", () => {
    console.log("Received SIGTERM");
    shutdownAndExit(0, "SIGTERM");
  });

  // handle unexpected errors: log everything first, then shutdown (behavior depends on env)
  process.on("uncaughtException", (err) => {
    console.error("Uncaught exception (handling):", err && err.stack ? err.stack : err);

    // In production: perform graceful shutdown and exit.
    // In development: only log, do not call shutdownAndExit automatically.
    if (process.env.NODE_ENV === "production" || process.env.FORCE_SHUTDOWN_ON_ERROR === "true") {
      // small delay so logs flush then run shutdown
      setTimeout(() => shutdownAndExit(1, "uncaughtException", err), 10);
    } else {
      console.warn("[dev] uncaughtException - skipping process exit. Set FORCE_SHUTDOWN_ON_ERROR=true to force exit.");
    }
  });

  process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled rejection at promise:", promise, "reason:", reason && reason.stack ? reason.stack : reason);

    if (process.env.NODE_ENV === "production" || process.env.FORCE_SHUTDOWN_ON_ERROR === "true") {
      setTimeout(() => shutdownAndExit(1, "unhandledRejection", reason), 10);
    } else {
      console.warn("[dev] unhandledRejection - skipping process exit. Set FORCE_SHUTDOWN_ON_ERROR=true to force exit.");
    }
  });

  // beforeExit/exit hooks to log (helpful when orchestrator kills container)
  process.on("beforeExit", (code) => {
    console.log(`process beforeExit event with code: ${code}`);
  });
  process.on("exit", (code) => {
    console.log(`process exit event with code: ${code}`);
    // Clear db watch interval on exit (best-effort)
    try { clearInterval(dbWatchHandle); } catch (e) { /* ignore */ }
  });
})();
