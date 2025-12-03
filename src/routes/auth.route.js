import express from "express";
import { checkAuth, login, logout, signup, updateProfile } from "../controllers/auth.controller.js";
import { protectRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

// Public routes
router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);

// Protected route
router.put("/update-profile", protectRoute, updateProfile);

// Auth check routes (BOTH supported)
router.get("/check", checkAuth);
router.get("/me", checkAuth);   // <-- ADD THIS LINE

export default router;
