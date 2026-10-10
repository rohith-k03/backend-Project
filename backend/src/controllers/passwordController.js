import crypto from "crypto";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { sendOtpEmail } from "../utils/sendEmail.js";

const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_GAP_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordPattern = /^(?=.*[A-Z])(?=.*\d).{8,}$/;

const normalizeEmail = (value) => String(value || "").trim().toLowerCase();

const generateOtp = () => crypto.randomInt(100000, 1000000).toString();

const hashOtp = (otp) =>
  crypto.createHmac("sha256", process.env.JWT_SECRET).update(otp).digest("hex");

const safeEqual = (a, b) => {
  const first = Buffer.from(a);
  const second = Buffer.from(b);
  return first.length === second.length && crypto.timingSafeEqual(first, second);
};

const clearOtp = (user) => {
  user.resetOtpHash = undefined;
  user.resetOtpExpires = undefined;
  user.resetOtpAttempts = 0;
};

export const forgotPassword = async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!emailPattern.test(email)) {
      return res.status(400).json({ message: "Enter a valid email address" });
    }

    const reply = {
      message: "If this email is registered, a recovery code has been sent",
    };

    const user = await User.findOne({ email }).select("+resetOtpSentAt");
    if (!user) {
      return res.json(reply);
    }

    const sentAt = user.resetOtpSentAt ? user.resetOtpSentAt.getTime() : 0;
    if (Date.now() - sentAt < RESEND_GAP_MS) {
      return res.json(reply);
    }

    const otp = generateOtp();
    user.resetOtpHash = hashOtp(otp);
    user.resetOtpExpires = new Date(Date.now() + OTP_TTL_MS);
    user.resetOtpAttempts = 0;
    user.resetOtpSentAt = new Date();
    await user.save({ validateBeforeSave: false });

    try {
      await sendOtpEmail(user.email, otp);
    } catch (error) {
      clearOtp(user);
      user.resetOtpSentAt = undefined;
      await user.save({ validateBeforeSave: false });
      return res
        .status(500)
        .json({ message: "Could not send the code, please try again" });
    }

    res.json(reply);
  } catch (error) {
    res.status(500).json({ message: "Something went wrong, try again" });
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();

    if (!emailPattern.test(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ message: "Enter the 6-digit code" });
    }

    const user = await User.findOne({ email }).select(
      "+resetOtpHash +resetOtpExpires +resetOtpAttempts"
    );

    if (!user || !user.resetOtpHash || user.resetOtpExpires < new Date()) {
      return res.status(400).json({ message: "Invalid or expired code" });
    }

    if (user.resetOtpAttempts >= MAX_ATTEMPTS) {
      clearOtp(user);
      await user.save({ validateBeforeSave: false });
      return res
        .status(429)
        .json({ message: "Too many attempts, request a new code" });
    }

    if (!safeEqual(user.resetOtpHash, hashOtp(otp))) {
      user.resetOtpAttempts += 1;
      await user.save({ validateBeforeSave: false });
      return res.status(400).json({ message: "Invalid or expired code" });
    }

    clearOtp(user);
    await user.save({ validateBeforeSave: false });

    const resetToken = jwt.sign(
      { id: user._id, purpose: "password-reset" },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.json({ message: "Code verified", resetToken });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong, try again" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!passwordPattern.test(newPassword)) {
      return res.status(400).json({
        message:
          "Password needs at least 8 characters, one uppercase letter and one number",
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    } catch (error) {
      return res
        .status(401)
        .json({ message: "Session expired, verify your email again" });
    }

    if (decoded.purpose !== "password-reset") {
      return res.status(401).json({ message: "Invalid reset session" });
    }

    const user = await User.findById(decoded.id).select("+password");
    if (!user) {
      return res.status(401).json({ message: "Invalid reset session" });
    }

    const alreadyUsed =
      user.passwordChangedAt &&
      decoded.iat * 1000 < user.passwordChangedAt.getTime();
    if (alreadyUsed) {
      return res
        .status(401)
        .json({ message: "Session expired, verify your email again" });
    }

    if (await user.matchPassword(newPassword)) {
      return res
        .status(400)
        .json({ message: "Choose a password you haven't used before" });
    }

    user.password = newPassword;
    await user.save();

    res.json({
      message: "Password updated, you have been signed out of other devices",
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong, try again" });
  }
};