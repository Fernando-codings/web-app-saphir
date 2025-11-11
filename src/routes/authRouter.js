import { Router } from "express";
import {
  register,
  login,
  logout,
  refreshToken,
} from "../controller/auth/authController.js";

export const router = Router();

router.post("/register", register); // inscription de l'utilisateur
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh", refreshToken);
