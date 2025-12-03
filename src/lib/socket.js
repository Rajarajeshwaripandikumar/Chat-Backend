// src/lib/socket.js
import express from "express";
import http from "http";
import { Server } from "socket.io";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cookie from "cookie";

dotenv.config();

// Express + HTTP server
const app = express();
const server = http.createServer(app);

// Ensure minimal defensive flags exist
try { server.__wasListened = false; } catch (e) { /* ignore */ }
try { server.__isShuttingDown = false; } catch (e) { /* ignore */ }

// If server emits 'listening', mark we actually bound to a port
if (server && typeof server.on === "function") {
  server.on("listening", () => {
    try { server.__wasListened = true; } catch (e) { /* ignore */ }
  });
}

// ENV config
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim());

const JWT_SECRET = process.env.JWT_SECRET || "my-very-secure-secret-key";
const COOKIE_NAME = process.env.JWT_COOKIE_NAME || "jwt";
const SINGLE_SESSION = process.env.SINGLE_SESSION === "true";

// Socket.io server (slightly relaxed ping settings)
const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true,
  },
  path: "/socket.io",
  pingInterval: 25000,
  pingTimeout: 60000,
});

// Presence: userId -> Set(socketIds)
const userSockets = new Map();

function getReceiverSocketId(userId) {
  const set = userSockets.get(String(userId));
  if (!set) return undefined;
  return Array.from(set.values())[0];
}

function getUserSocketIds(userId) {
  const set = userSockets.get(String(userId));
  return set ? Array.from(set.values()) : [];
}

function addSocketForUser(userId, socketId) {
  const key = String(userId);
  const set = userSockets.get(key) || new Set();
  set.add(socketId);
  userSockets.set(key, set);
}

function removeSocketForUser(userId, socketId) {
  const key = String(userId);
  const set = userSockets.get(key);
  if (!set) return;
  set.delete(socketId);
  if (set.size === 0) userSockets.delete(key);
}

function broadcastOnlineUsers(nsp) {
  try {
    nsp.emit("getOnlineUsers", Array.from(userSockets.keys()));
  } catch (err) {
    console.warn("broadcastOnlineUsers error:", err);
  }
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function extractTokenFromSocketHandshake(socket) {
  try {
    if (socket.handshake?.auth?.token) return socket.handshake.auth.token;
    if (socket.handshake?.query?.token) return socket.handshake.query.token;

    const authHeader =
      socket.request?.headers?.authorization ||
      socket.handshake?.headers?.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      return authHeader.split(" ")[1];
    }

    const cookieHeader = socket.request?.headers?.cookie || "";
    if (cookieHeader) {
      const parsed = cookie.parse(cookieHeader);
      return parsed[COOKIE_NAME] || parsed.jwt || parsed.token || null;
    }

    return null;
  } catch (err) {
    console.warn("extractTokenFromSocketHandshake error:", err);
    return null;
  }
}

function maskToken(t) {
  try {
    if (!t || typeof t !== "string") return "null";
    if (t.length <= 8) return "****";
    return "****" + t.slice(-4);
  } catch {
    return "****";
  }
}

// Namespace: /chat
const chatNsp = io.of("/chat");

// Auth middleware
chatNsp.use((socket, next) => {
  const token = extractTokenFromSocketHandshake(socket);
  if (!token) {
    console.warn("[chat middleware] missing token");
    return next(new Error("Authentication error"));
  }

  console.debug(`[chat middleware] handshake token: ${maskToken(token)}`);

  const decoded = verifyToken(token);
  const userId = decoded?.userId || decoded?.id || decoded?.sub;

  if (!userId) {
    console.warn("[chat middleware] invalid token (no userId)");
    return next(new Error("Authentication error"));
  }

  socket.data.userId = String(userId);
  next();
});

// Connection handler
chatNsp.on("connection", (socket) => {
  const socketId = socket.id;
  const userId = socket.data.userId;

  console.log(`[chat] connected: ${socketId} user=${userId}`);

  // SINGLE_SESSION handling
  if (SINGLE_SESSION) {
    try {
      console.log(`[chat] SINGLE_SESSION: removing old sockets for user=${userId}`);
      const prevSockets = getUserSocketIds(userId);
      prevSockets.forEach((prevId) => {
        if (prevId !== socketId) {
          const prev = chatNsp.sockets.get(prevId);
          if (prev) {
            console.log(`[chat] disconnecting previous socket ${prevId}`);
            try { prev.disconnect(true); } catch (e) { /* ignore */ }
          }
        }
      });
      userSockets.delete(String(userId));
    } catch (err) {
      console.warn("[chat] SINGLE_SESSION error:", err);
    }
  }

  addSocketForUser(userId, socketId);
  socket.join(String(userId));

  broadcastOnlineUsers(chatNsp);

  socket.emit("connected", { message: "Connected to /chat", userId });

  socket.on("error", (err) => {
    console.error(`[chat:${socketId}] error:`, err);
  });

  socket.on("disconnect", (reason) => {
    if (["transport close", "io server disconnect", "forced close"].includes(reason)) {
      console.log(`[chat:${socketId}] disconnect (special): ${reason}`);
    } else {
      console.log(`[chat:${socketId}] disconnect: ${reason}`);
    }
    removeSocketForUser(userId, socketId);
    broadcastOnlineUsers(chatNsp);
  });

  socket.on("sendMessage", (payload, ack) => {
    try {
      const { toUserId, text } = payload || {};
      if (!toUserId || !text) {
        ack?.({ ok: false, error: "invalid_payload" });
        return;
      }

      const msg = {
        id: Date.now().toString(),
        senderId: userId,
        toUserId,
        text,
        createdAt: new Date().toISOString(),
      };

      chatNsp.to(String(toUserId)).emit("newMessage", msg);
      chatNsp.to(String(userId)).emit("messageSent", msg);

      ack?.({ ok: true, message: msg });
    } catch (err) {
      console.error(`[chat:${socketId}] sendMessage error:`, err);
      ack?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("typing", ({ toUserId } = {}) => {
    try {
      if (toUserId) chatNsp.to(String(toUserId)).emit("typing", { from: userId });
    } catch (err) {
      console.warn(`[chat:${socketId}] typing error:`, err);
    }
  });
});

function sendDirectMessage(toUserId, event, payload) {
  try {
    io.of("/chat").to(String(toUserId)).emit(event, payload);
  } catch (err) {
    console.warn("sendDirectMessage error:", err);
  }
}

/** Gracefully close HTTP + Socket.IO */
export async function closeHttpAndIo() {
  console.log("[server] closing HTTP server + Socket.IO...");

  // Prevent duplicate close attempts
  if (server && server.__isShuttingDown) {
    console.log("[server] close already in progress, skipping duplicate close.");
  } else {
    try { server.__isShuttingDown = true; } catch (e) { /* ignore */ }
  }

  // Close HTTP server (defensive checks)
  if (server && typeof server.close === "function") {
    try {
      const wasListened = !!server.__wasListened;
      let hasAddress = false;
      try {
        hasAddress = typeof server.address === "function" && server.address() !== null;
      } catch (e) { hasAddress = false; }

      const appearsRunning = (typeof server.listening !== "undefined" ? !!server.listening : wasListened || hasAddress);

      if (appearsRunning) {
        await new Promise((resolve) => {
          try {
            server.close((err) => {
              if (err) {
                // ignore "not running" style errors
                if (err && (err.code === "ERR_SERVER_NOT_RUNNING" || err.code === "ERR_SERVER_ALREADY_CLOSED")) {
                  console.warn("[server] http close warning (ignored):", err && err.code);
                  return resolve();
                }
                console.warn("[server] http close error:", err);
                return resolve();
              }
              return resolve();
            });
          } catch (err) {
            console.warn("[server] http close exception:", err);
            return resolve();
          }
        });
      } else {
        console.log("[server] http server not running/never started; skipping close.");
      }
    } catch (err) {
      console.warn("[server] http close top-level error:", err);
    }
  } else {
    console.log("[server] no http server.close() available (skipping).");
  }

  // Close socket.io with callback + fallback
  try {
    if (io && typeof io.close === "function") {
      await new Promise((resolve) => {
        let finished = false;

        try {
          // io.close accepts callback in v4; wrap defensively
          io.close(() => {
            if (!finished) {
              finished = true;
              console.log("[server] io.close callback fired");
              resolve();
            }
          });
        } catch (err) {
          // In case io.close throws synchronously (rare), log and resolve
          console.warn("[server] io.close threw:", err);
          if (!finished) {
            finished = true;
            resolve();
          }
        }

        // fallback timeout so we don't hang indefinitely
        setTimeout(() => {
          if (!finished) {
            finished = true;
            console.warn("[server] io.close fallback timeout");
            resolve();
          }
        }, 5000).unref?.();
      });
    } else {
      console.log("[server] no io.close() available (skipping).");
    }
  } catch (err) {
    console.warn("[server] io close error:", err);
  }

  console.log("[server] HTTP + Socket.IO fully closed.");
}

/**
 * createGracefulExit:
 * Returns a shutdown function WITHOUT registering any signal listeners here.
 */
export function createGracefulExit({ onCloseComplete } = {}) {
  return async function graceful() {
    console.log("[server] graceful shutdown started...");
    try {
      await closeHttpAndIo();
    } catch (err) {
      console.error("[server] graceful shutdown error:", err);
    } finally {
      console.log("[server] graceful shutdown complete.");
      if (typeof onCloseComplete === "function") {
        try { await onCloseComplete(); }
        catch (e) { console.warn("onCloseComplete failure:", e); }
      }
    }
  };
}

export { app, server, io, getReceiverSocketId, getUserSocketIds, sendDirectMessage };
