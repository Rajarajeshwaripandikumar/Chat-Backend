// src/lib/db.resilient.js
import mongoose from "mongoose";

let _isConnected = false;
let _listenersAttached = false;

const MONGO_ENV_NAMES = ["MONGODB_URI", "MONGO_URI"];

function getMongoUri() {
  for (const name of MONGO_ENV_NAMES) {
    const val = process.env[name];
    if (val) {
      const preview = String(val).slice(0, 40) + (String(val).length > 40 ? "..." : "");
      console.log(`ℹ️ Using env ${name}: ${preview}`);
      return val;
    }
  }
  // RETURN null to make the caller decide whether to fallback or fail
  return null;
}

/**
 * connectDB:
 *  - Retries connection with exponential backoff on failure
 *  - Resolves when connected (returns mongoose.connection)
 *  - Does NOT call process.exit() on transient failures
 */
export async function connectDB({ maxAttempts = 10, initialDelayMs = 1000, fallbackLocal = true } = {}) {
  // prefer env-provided URI
  const envUri = getMongoUri();
  const MONGO_URI = envUri || (fallbackLocal ? "mongodb://127.0.0.1:27017/chintu" : null);

  if (!MONGO_URI) {
    const msg = "MONGODB_URI or MONGO_URI environment variable is not defined and no fallback available.";
    console.error("❌", msg);
    throw new Error(msg);
  }

  // Avoid reconnecting if already connected (useful during HMR/dev)
  if (_isConnected || mongoose.connection.readyState === 1) {
    console.log("⚠️ MongoDB already connected. Reusing existing connection.");
    _isConnected = true;
    return mongoose.connection;
  }

  mongoose.set("strictQuery", true);

  // Attach listeners only once to avoid duplicate handlers on repeated connect attempts (HMR/dev)
  if (!_listenersAttached) {
    _listenersAttached = true;

    mongoose.connection.on("connected", () => {
      _isConnected = true;
      console.log("✅ MongoDB connection: connected");
    });

    mongoose.connection.on("reconnected", () => {
      _isConnected = true;
      console.log("✅ MongoDB connection: reconnected");
    });

    mongoose.connection.on("error", (err) => {
      console.error("❌ MongoDB error:", err && err.stack ? err.stack : err);
    });

    mongoose.connection.on("disconnected", () => {
      _isConnected = false;
      console.warn("⚠️ MongoDB disconnected. Driver will attempt automatic reconnect if possible.");
    });

    mongoose.connection.on("close", () => {
      _isConnected = false;
      console.log("ℹ️ MongoDB connection closed (close event).");
    });

    // graceful shutdown hooks (helpful during dev and in production)
    const gracefulClose = async () => {
      try {
        await mongoose.disconnect();
        _isConnected = false;
        console.log("🛑 MongoDB connection closed by process signal.");
      } catch (err) {
        console.warn("⚠️ Error during mongoose.disconnect on process signal:", err && err.stack ? err.stack : err);
      }
      // do not call process.exit here; let the caller decide
    };

    process.on("SIGINT", gracefulClose);
    process.on("SIGTERM", gracefulClose);
  }

  // attempt connect with retries
  let attempt = 0;
  async function tryConnect() {
    attempt += 1;
    try {
      console.log(`[mongo] connecting (attempt ${attempt})...`);
      await mongoose.connect(MONGO_URI, {
        // explicit, modern options (Mongoose 6+ uses these by default but explicit helps clarity)
        useNewUrlParser: true,
        useUnifiedTopology: true,
        family: 4, // prefer IPv4
        maxPoolSize: 20,
        connectTimeoutMS: 10000,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 0,
      });
      _isConnected = true;
      console.log("✅ MongoDB connected successfully!");
      return mongoose.connection;
    } catch (err) {
      console.error(`[mongo] connect error (attempt ${attempt}):`, err && err.stack ? err.stack : err);
      if (attempt >= maxAttempts) {
        const msg = `[mongo] failed to connect after ${attempt} attempts`;
        console.error(msg);
        throw new Error(msg);
      }
      const delay = Math.min(initialDelayMs * 2 ** (attempt - 1), 30000);
      console.log(`[mongo] retrying in ${delay}ms...`);
      await new Promise((res) => setTimeout(res, delay));
      return tryConnect();
    }
  }

  return tryConnect();
}

/**
 * closeDB: gracefully close mongoose connection
 */
export async function closeDB() {
  try {
    if (mongoose.connection && mongoose.connection.readyState) {
      await mongoose.disconnect();
      _isConnected = false;
      console.log("🛑 MongoDB connection closed.");
    } else {
      console.log("ℹ️ MongoDB no active connection to close.");
    }
  } catch (err) {
    console.warn("⚠️ Error closing MongoDB connection:", err && err.stack ? err.stack : err);
  }
}

/**
 * isConnected getter
 */
export function isConnected() {
  return _isConnected;
}

/**
 * Optional helper: provide a small health-check middleware factory
 * Usage:
 *   app.use('/_health', mongoHealthMiddleware());
 * returns 200 if db connected, 503 otherwise.
 */
export function mongoHealthMiddleware() {
  return (req, res) => {
    if (isConnected()) {
      return res.status(200).json({ status: "ok", mongo: "connected" });
    }
    return res.status(503).json({ status: "unavailable", mongo: "disconnected" });
  };
}
