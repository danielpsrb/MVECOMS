import express, { Router } from 'express';
import {
  userRegistration,
  verifyUserEmail,
} from "../controllers/auth.controller";

const router:Router = express.Router();

router.post('/user/signup', userRegistration);
router.post('/user/signup/verify-email', verifyUserEmail);

export default router;
