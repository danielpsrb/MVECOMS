import  { NextFunction, Request, Response} from 'express';
import bcrypt from "bcryptjs";
import jwt, {SignOptions} from "jsonwebtoken";
import {
  validateRegistrationData,
  checkOtpRestrictions,
  sendOtp,
  trackOtpRequests,
  verifyEmailOtp
} from "../utils/auth.helper";
import prisma from '@packages/libs/prisma';
import { ValidationError } from '@packages/error-handler';

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_MAIN";
const JWT_TEMP_SECRET = process.env.JWT_TEMP_SECRET || "CHANGE_ME_TEMP";
const SALT_ROUNDS = 10;

function signTempToken(payload: object) {
  const options: SignOptions = { expiresIn: "10m" };
  return jwt.sign(payload, JWT_TEMP_SECRET as string, options);
}

function signMainToken(payload: object) {
  const options: SignOptions = { expiresIn: "7d" };
  return jwt.sign(payload, JWT_SECRET as string, options);
}

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

