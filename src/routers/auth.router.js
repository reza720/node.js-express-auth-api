const express = require("express");
const router = express.Router();

router.post("/auth/singup");
router.get("/auth/verify-email");
router.post("/auth/resend-verification-email");
router.post("/auth/login");
router.post("/auth/logout");
router.patch("/auth/change-password");
router.post("/auth/forgot-password");
router.post("/auth/reset-password");
router.post("auth/refresh");
router.get("/auth/me");
router.delete("/auth/me");

module.exports= router;