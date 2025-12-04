import express from "express";
import { 
  checkAuth, 
  login, 
  logout, 
  signup, 
  updateProfile,
  forgotPassword,
  resetPassword
} from "../controllers/auth.controller.js";

import { protectRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public routes
router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);

// NEW: Forgot + Reset password routes
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

// Protected route
router.put("/update-profile", protectRoute, updateProfile);

// Auth check routes
router.get("/check", checkAuth);
router.get("/me", checkAuth);

export default router;
