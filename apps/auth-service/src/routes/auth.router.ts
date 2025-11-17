import express, { Router } from 'express';
import {
  userRegistration,
  verifyUserEmail,
  loginUser,
  userForgotPassword,
  verifyUserForgotPassword,
  resetUserPassword,
} from "../controllers/auth.controller";

const router:Router = express.Router();

router.post('/user/signup', userRegistration);
router.post('/user/signup/verify-email', verifyUserEmail);
router.post('/user/login', loginUser);
router.post('/user/forgot-password', userForgotPassword);
router.post('/user/forgot-password/verify-otp', verifyUserForgotPassword);
router.post('/user/reset-password', resetUserPassword);

export default router;
