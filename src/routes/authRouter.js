import { Router } from "express";
import { register } from "../controller/authController.js";

export const router = Router()

router.post("/register", register)