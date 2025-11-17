import bcrypt from "bcryptjs";
import crypto from 'crypto';
import qrcode from "qrcode";
import speakeasy from "speakeasy";
import prisma from '@packages/libs/prisma';
import { ValidationError } from '@packages/error-handler';
import redis from '@packages/libs/redis';
import { sendEmail } from './sendMail';
import { Request, Response, NextFunction } from "express";
// import path from 'path';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Password regex min 8 karakter dengan kombinasi huruf dan angka
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

const BCRYPT_SALT_ROUNDS = 10;

// validate register user or seller data
export const validateRegistrationData = (data: any, userType: "user" | "seller") => {
  // Implement validation logic here
  const { name, email, password, confirmPassword, phone_number, country } =
    data;

  if (
    !name ||
    !email ||
    !password ||
    !confirmPassword ||
    (userType === "seller" && (!phone_number || !country))
  ) {
    throw new ValidationError("Missing required fields");
  }

  if (!emailRegex.test(email)) {
    throw new ValidationError("Invalid email format");
  }

  // cek password minimal 8 karakter, huruf + angka
  if (!passwordRegex.test(password)) {
    throw new ValidationError(
      "Password must be at least 8 characters and contain both letters and numbers"
    );
  }

  // cek password dan confirmPassword sama
  if (password !== confirmPassword) {
    throw new ValidationError("Password and confirm password do not match");
  }
};

export const checkOtpRestrictions = async (email:string) => {
  if (await redis.get(`otp_lock:${email}`)) {
    throw new ValidationError('Account locked due to multiple failed attempts!. Try again after 30 minutes.');
  }

  if (await redis.get(`otp_spam_lock:${email}`)) {
    throw new ValidationError('Too many OTP requests! Try again after 1 hour.');
  }

  if (await redis.get(`otp_cooldown:${email}`)) {
    throw new ValidationError('Please wait 1 minute before requesting a new OTP.');
  }
}

export const sendOtp = async (name: string, email: string, template: string) => {
  const otp = crypto.randomInt(100000, 999999).toString();

  await sendEmail(email, "Verify your email", template, {name,otp});

  await redis.set(`otp:${email}`, otp, "EX", 300); // OTP valid for 5 minutes
  await redis.set(`otp_cooldown:${email}`, 'true', "EX", 60); // Cooldown of 1 minute

  // Simulate sending email
  console.log(`Sending OTP ${otp} to email ${email} using template ${template}`);
};

export const trackOtpRequests = async (email: string) => {
  const otpRequestKey = `otp_requests_count:${email}`;

  let otpRequest = parseInt(await redis.get(otpRequestKey) || '0');

  if (otpRequest >= 2) {
    await redis.set(`otp_spam_lock:${email}`, 'locked', "EX", 3600); // 1 hour lock
    throw new ValidationError('Too many OTP requests! Try again after 1 hour.');
  }

  await redis.set(otpRequestKey, (otpRequest + 1).toString(), "EX", 3600); // Track request for 1 hour
}

export const verifyEmailOtp = async (email: string, otp: string) => {
  const storedOtp = await redis.get(`otp:${email}`);
  if (!storedOtp) {
    throw new ValidationError("Invalid or expired OTP!");
  }

  const failedAttemptsKey = `otp_attempts:${email}`;
  const failedAttempts = parseInt((await redis.get(failedAttemptsKey)) || "0");

  if (storedOtp !== otp) {
    if (failedAttempts >= 2) {
      await redis.set(`otp_lock:${email}`, "locked", "EX", 2700);
      await redis.del(`otp:${email}`, failedAttemptsKey);
      throw new ValidationError(
        "Account locked due to multiple failed attempts! Try again after 45 minutes."
      );
    }

    await redis.set(
      failedAttemptsKey,
      (failedAttempts + 1).toString(),
      "EX",
      300
    );

    throw new ValidationError(
      `Invalid OTP! You have ${2 - failedAttempts} attempts left.`
    );
  }

  await redis.del(`otp:${email}`, failedAttemptsKey);
};

export const handleForgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
  userType: "user" | "seller"
) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new ValidationError("Email is required");
    }
    if (!emailRegex.test(email)) {
      throw new ValidationError("Invalid email format");
    }
    // find user/seller in database
    const user = userType === "user" && await prisma.users.findUnique({ where: { email } })

    if (!user) {
      throw new ValidationError(`${userType} with this email does not exist`);
    }

    await checkOtpRestrictions(email);
    await trackOtpRequests(email);

    //Generate otp and send email to reset password
    await sendOtp(email, user.name, "forgot-password-user-mail");

    res.status(200).json({
      message: 'OTP sent to email. Please check your email to reset your password.',
    })
  } catch (error) {
    return next(error);
  }
};

export const verifyForgotPasswordOtp = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      throw new ValidationError("All fields are required");
    }

    await verifyEmailOtp(email, otp);

    res.status(200).json({
      message: 'OTP verified successfully. You can now reset your password.',
    });
  } catch (error) {
    return next(error);
  }
};
