// src/lib/utils.js
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "my-very-secure-secret-key";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const COOKIE_NAME = process.env.JWT_COOKIE_NAME || "jwt";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

export const generateToken = (userId, res) => {
  const token = jwt.sign(
    { userId: String(userId), id: String(userId) },  // BOTH keys supported
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  try {
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: false,          // IMPORTANT for localhost
      sameSite: "none",       // REQUIRED for 5173 -> 5000
      maxAge: COOKIE_MAX_AGE,
      path: "/",
    });
  } catch (e) {
    console.warn("[generateToken] cookie set failed:", e?.message);
  }

  return token;
};
