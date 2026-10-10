import { Router } from "express";
import rateLimit from "express-rate-limit";
import { register, login, getMe } from "../controllers/authController.js";
import {
  forgotPassword,
  verifyOtp,
  resetPassword,
} from "../controllers/passwordController.js";
import protect from "../middleware/auth.js";

const router = Router();

const buildLimiter = (max, message) =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message },
  });

const authLimiter = buildLimiter(20, "Too many attempts, please try again later");
const forgotLimiter = buildLimiter(5, "Too many code requests, try again later");
const otpLimiter = buildLimiter(10, "Too many attempts, try again later");
const resetLimiter = buildLimiter(10, "Too many attempts, try again later");

router.post("/register", authLimiter, register);
router.post("/login", authLimiter, login);
router.get("/me", protect, getMe);

router.post("/forgot-password", forgotLimiter, forgotPassword);
router.post("/verify-otp", otpLimiter, verifyOtp);
router.post("/reset-password", resetLimiter, resetPassword);

export default router;