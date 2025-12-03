// controllers/auth.controller.js
import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "my-very-secure-secret-key";
const COOKIE_NAME = process.env.JWT_COOKIE_NAME || "jwt";

// Helper to extract token from cookie or Authorization header
function getTokenFromReq(req) {
  // cookie-based
  if (req.cookies && req.cookies[COOKIE_NAME]) return req.cookies[COOKIE_NAME];

  // header-based: "Bearer <token>"
  const auth = req.headers?.authorization;
  if (auth && auth.startsWith("Bearer ")) return auth.split(" ")[1];

  return null;
}

// Signup
export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ fullName, email, password: hashedPassword });
    await newUser.save();

    // Generate token, set cookie, and return token in JSON (dual support)
    const token = generateToken(newUser._id, res);

    res.status(201).json({
      _id: newUser._id,
      fullName: newUser.fullName,
      email: newUser.email,
      profilePic: newUser.profilePic,
      token, // include token so clients expecting JSON can store it
    });
  } catch (error) {
    console.log("Error in signup controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Login
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

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

// Logout
export const logout = (req, res) => {
  try {
    // clear cookie with same name and options
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

// updateProfile: requires protectRoute to have set req.user (or use checkAuth first)
// Ensure req.user may contain .id or .userId depending on middleware
export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user?.id || req.user?.userId || req.user?._id;

    if (!userId) return res.status(401).json({ message: "Unauthorized" });
    if (!profilePic) return res.status(400).json({ message: "Profile pic is required" });

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

// checkAuth: public route that verifies token from cookie or header and returns user
export const checkAuth = async (req, res) => {
  try {
    const token = getTokenFromReq(req);
    if (!token) return res.status(200).json({ user: null }); // not authenticated

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(200).json({ user: null }); // invalid token => not authenticated
    }

    const userId = decoded?.userId || decoded?.id || decoded?.sub;
    if (!userId) return res.status(200).json({ user: null });

    const user = await User.findById(userId).select("-password");
    if (!user) return res.status(200).json({ user: null });

    // return user object
    res.status(200).json({ user });
  } catch (error) {
    console.log("Error in checkAuth controller:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
