import  { NextFunction, Request, Response} from 'express';
import bcrypt from "bcryptjs";
import jwt, {SignOptions} from "jsonwebtoken";
import {
  validateRegistrationData,
  checkOtpRestrictions,
  sendOtp,
  trackOtpRequests,
  verifyEmailOtp,
  generate2FASecret,
  verify2FACode,
  generateRecoveryCodes,
  verifyAndConsumeRecoveryCode,
} from "../utils/auth.helper";
import prisma from '@packages/libs/prisma';
import { ValidationError, AuthError } from '@packages/error-handler';
import { setCookie } from '../utils/cookies/setCookie';

const SALT_ROUNDS = 10;
const JWT_TEMP_SECRET = process.env.JWT_TEMP_SECRET;
const JWT_MAIN_SECRET = process.env.JWT_MAIN_SECRET;

// Register a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
  try {
    validateRegistrationData(req.body, "user");
    const { name, email } = req.body;

    const existingUser = await prisma.users.findUnique({ where: { email } });
    if (existingUser) {
      return next(new ValidationError("User already exists with this email"));
    }

    await checkOtpRestrictions(email, next);
    await trackOtpRequests(email, next);
    await sendOtp(name, email, "user-activation-mail");

    res
      .status(200)
      .json({
        message:
          "OTP sent to email. Please check your email and verify your account.",
      });
  } catch (error) {
    return next(error);
  }
};

// Verify email user with OTP
export const verifyUserEmail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, otp, password, name } = req.body;

    if (!email || !otp || !password || !name) {
      return next(new ValidationError("All fields are required"));
    }

    // Step 1: verify OTP first
    await verifyEmailOtp(email, otp);

    // Step 2: after OTP is valid, check if email already exists
    const existingUser = await prisma.users.findUnique({ where: { email } });
    if (existingUser) {
      return next(new ValidationError("User already exists with this email"));
    }

    // Step 3: hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Step 4: create user
    await prisma.users.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      status: "success",
      message: "User registered successfully",
    });
  } catch (error) {
    return next(error);
  }
};

export const loginUser = async(req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email || !password) {
      return next(new ValidationError("Email and password are required"));
    }

    if (!emailRegex.test(email)) {
      return next(new ValidationError("Invalid email format"));
    }

    const user = await prisma.users.findUnique({ where: { email } });

    if (!user) {
      return next(new AuthError("Invalid credentials"));
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return next(new AuthError("Invalid credentials"));
    }

    // Generate temp token and main token for 2FA
    const tempToken = jwt.sign(
      { userId: user.id },
      JWT_TEMP_SECRET as string,
        {
          expiresIn: "6m",
        }
    );
    const mainToken = jwt.sign(
      { userId: user.id },
        JWT_MAIN_SECRET as string,
        {
          expiresIn: "10m",
        }
    );

    setCookie(res, 'temp_token', tempToken);
    setCookie(res, 'main_token', mainToken);

    if (!user.is2FAEnabled) {
      return res.status(200).json({
        status: "success",
        message:
          "Login successful. Two Factor Authentication is not enabled. Please enable it for better security.",
      });
    }

  } catch (error) {
    return next(error);
  }
}
