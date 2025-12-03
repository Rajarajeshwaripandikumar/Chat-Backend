// src/middleware/auth.middleware.js
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

const COOKIE_NAME = process.env.JWT_COOKIE_NAME || "jwt";
const JWT_SECRET = process.env.JWT_SECRET;

export const protectRoute = async (req, res, next) => {
  try {
    if (!JWT_SECRET) {
      console.error("JWT_SECRET is not defined!");
      return res.status(500).json({ message: "Server misconfiguration" });
    }

    // 1) extract token from Authorization header (case-insensitive) or cookie
    let token = null;
    const authHeader = req.headers && (req.headers.authorization || req.headers.Authorization);
    if (authHeader && String(authHeader).startsWith("Bearer ")) {
      token = String(authHeader).split(" ")[1];
    } else if (req.cookies && req.cookies[COOKIE_NAME]) {
      token = req.cookies[COOKIE_NAME];
    }

    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No token provided" });
    }

    // 2) verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      // If token expired, clear cookie (if present) to help client UX
      if (err.name === "TokenExpiredError") {
        if (req.cookies && req.cookies[COOKIE_NAME]) {
          res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            path: "/",
          });
        }
        return res.status(401).json({ message: "Unauthorized - Token expired" });
      }
      return res.status(401).json({ message: "Unauthorized - Invalid token" });
    }

    // Prefer decoded.id (matches generateToken), but accept legacy keys
    const userId = decoded?.id || decoded?.userId || decoded?.sub;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized - Invalid token payload" });
    }

    // 3) fetch user (exclude password)
    const user = await User.findById(userId).select("-password");
    if (!user) {
      // generic message to avoid enumeration
      return res.status(401).json({ message: "Unauthorized" });
    }

    // attach minimal user info to req.user and res.locals for downstream
    req.user = {
      id: user._id,
      email: user.email,
      fullName: user.fullName || user.name || null,
      profilePic: user.profilePic || null,
    };
    res.locals.user = req.user;

    next();
  } catch (error) {
    console.error("Error in protectRoute middleware:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
