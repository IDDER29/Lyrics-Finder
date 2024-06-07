import { Router } from "express";
const router = Router();
import {
  logIn,
  forgotPassword,
  resetPassword,
  generateVerificationCode, verifyCodeAndCreateUser
} from "../controllers/auth-controller";
import { validate } from "../middlewares/validate";
import { registerValidationRules } from "../validators/registerValidation";
import { logInValidationRules } from "../validators/logInValidation";

router.post("/request-verification", generateVerificationCode);
router.post("/verify-and-create", registerValidationRules, validate, verifyCodeAndCreateUser);
router.post("/login", logInValidationRules, validate, logIn);
router.post("/forgotPassword", forgotPassword);
router.put("/resetPassword/:token", resetPassword);

export { router as authRouters };
