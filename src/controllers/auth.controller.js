// controllers/auth.controller.js
import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

import crypto from "crypto";
import nodemailer from "nodemailer";
import { Resend } from "resend"; // 🔹 Resend

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "my-very-secure-secret-key";
const COOKIE_NAME = process.env.JWT_COOKIE_NAME || "jwt";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// choose how to send email: "gmail", "resend", or fallback "log"
const EMAIL_PROVIDER = process.env.EMAIL_PROVIDER || "log";

// Helper to extract token from cookie or Authorization header
function getTokenFromReq(req) {
  // cookie-based
  if (req.cookies && req.cookies[COOKIE_NAME]) return req.cookies[COOKIE_NAME];

  // header-based: "Bearer <token>"
  const auth = req.headers?.authorization;
  if (auth && auth.startsWith("Bearer ")) return auth.split(" ")[1];

  return null;
}

// =====================
// EMAIL SENDER SETUP
// =====================

let mailer = null;        // for Gmail
let resendClient = null;  // for Resend

if (EMAIL_PROVIDER === "gmail") {
  // Use Gmail SMTP (good for LOCAL dev only)
  mailer = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS, // app password
    },
  });

  mailer.verify((err, success) => {
    if (err) {
      console.error("❌ Error verifying Gmail SMTP transporter:", err);
    } else {
      console.log("✅ Gmail SMTP transporter is ready to send emails");
    }
  });
} else if (EMAIL_PROVIDER === "resend") {
  if (!process.env.RESEND_API_KEY) {
    console.error("❌ RESEND_API_KEY is missing. Emails will not be sent.");
  } else {
    resendClient = new Resend(process.env.RESEND_API_KEY);
    console.log("✅ Resend client initialized");
  }
} else {
  console.log("📧 EMAIL_PROVIDER=log → emails will be logged, not sent");
}

// helper to send reset email (gmail / resend / log)
async function sendResetEmail(to, resetUrl) {
  const from =
    process.env.MAIL_FROM ||
    process.env.GMAIL_USER ||
    "no-reply@example.com";

  // --- RESEND ---
  if (EMAIL_PROVIDER === "resend" && resendClient) {
    const { error } = await resendClient.emails.send({
      from,
      to,
      subject: "Reset your Chintu password",
      html: `
        <p>You requested a password reset for your Chintu account.</p>
        <p>Click the link below to reset your password (valid for 10 minutes):</p>
        <p>
          <a href="${resetUrl}" target="_blank" 
             style="display:inline-block;padding:10px 16px;background:#4f46e5;color:#fff;
                    text-decoration:none;border-radius:6px;font-weight:600;">
            Reset Password
          </a>
        </p>
        <p>If you did not request this, you can ignore this email.</p>
      `,
    });

    if (error) {
      console.error("❌ Resend send error:", error);
      throw new Error("Failed to send reset email");
    }

    return;
  }

  // --- GMAIL ---
  if (EMAIL_PROVIDER === "gmail" && mailer) {
    await mailer.sendMail({
      to,
      from,
      subject: "Reset your Chintu password",
      html: `
        <p>You requested a password reset for your Chintu account.</p>
        <p>Click the link below to reset your password (valid for 10 minutes):</p>
        <p>
          <a href="${resetUrl}" target="_blank" 
             style="display:inline-block;padding:10px 16px;background:#4f46e5;color:#fff;
                    text-decoration:none;border-radius:6px;font-weight:600;">
            Reset Password
          </a>
        </p>
        <p>If you did not request this, you can ignore this email.</p>
      `,
    });
    return;
  }

  // --- LOG ONLY (fallback) ---
  console.log("📧 [log only] Password reset email");
  console.log("   To:", to);
  console.log("   Link:", resetUrl);
}

// =====================
// SIGNUP
// =====================
export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ fullName, email, password: hashedPassword });
    await newUser.save();

    const token = generateToken(newUser._id, res);

    res.status(201).json({
      _id: newUser._id,
      fullName: newUser.fullName,
      email: newUser.email,
      profilePic: newUser.profilePic,
      token,
    });
  } catch (error) {
    console.log("Error in signup controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================
// LOGIN
// =====================
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = generateToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
      token,
    });
  } catch (error) {
    console.log("Error in login controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================
// LOGOUT
// =====================
export const logout = (req, res) => {
  try {
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      path: "/",
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.log("Error in logout controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================
// UPDATE PROFILE
// =====================
export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user?.id || req.user?.userId || req.user?._id;

    if (!userId) return res.status(401).json({ message: "Unauthorized" });
    if (!profilePic)
      return res.status(400).json({ message: "Profile pic is required" });

    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: uploadResponse.secure_url },
      { new: true }
    ).select("-password");

    res.status(200).json({ user: updatedUser });
  } catch (error) {
    console.log("Error in update profile:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================
// CHECK AUTH
// =====================
export const checkAuth = async (req, res) => {
  try {
    const token = getTokenFromReq(req);
    if (!token) return res.status(200).json({ user: null });

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(200).json({ user: null });
    }

    const userId = decoded?.userId || decoded?.id || decoded?.sub;
    if (!userId) return res.status(200).json({ user: null });

    const user = await User.findById(userId).select("-password");
    if (!user) return res.status(200).json({ user: null });

    res.status(200).json({ user });
  } catch (error) {
    console.log("Error in checkAuth controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================================================
//  FORGOT PASSWORD  (POST /api/auth/forgot-password)
// =====================================================
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email)
      return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email });

    // For security, don't reveal whether user exists
    if (!user) {
      return res.status(200).json({
        ok: true,
        message: "If that email exists, a reset link was sent",
      });
    }

    // Generate random token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Hash token and save to DB with expiry
    user.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

    await user.save();

    // Build frontend URL
    const resetUrl = `${FRONTEND_URL}/reset-password/${resetToken}`;

    console.log("🔗 Password reset link:", resetUrl);

    try {
      await sendResetEmail(user.email, resetUrl);

      return res.status(200).json({
        ok: true,
        message: "If that email exists, a reset link was sent",
      });
    } catch (mailErr) {
      console.error("❌ Error sending reset email:", mailErr);

      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();

      return res.status(500).json({ message: "Failed to send reset email" });
    }
  } catch (error) {
    console.error("❌ Error in forgotPassword:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// =====================================================
//  RESET PASSWORD  (POST /api/auth/reset-password/:token)
// =====================================================
export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    // Hash token to match DB
    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid or expired reset token" });
    }

    // Update password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Clear reset fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({ ok: true, message: "Password reset successful" });
  } catch (error) {
    console.log("Error in resetPassword:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
