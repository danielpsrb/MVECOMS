import crypto from 'crypto';
import { ValidationError } from '../../../../packages/error-handler';
import redis from '../../../../packages/libs/redis';
import { sendEmail } from './sendMail';
import { NextFunction } from 'express';
import path from 'path';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// validate regis
export const validateRegistrationData = (data: any, userType: "user" | "seller") => {
  // Implement validation logic here
  const { name, email, password, phone_number, country } = data;

  if (
    !name || !email || !password || (userType === "seller" && (!phone_number || !country))
  ) {
    throw new ValidationError('Missing required fields');
  }

  if (!emailRegex.test(email)) {
    throw new ValidationError("Invalid email format");
  }
};

export const checkOtpRestrictions = async (email:string, next:NextFunction) => {
  if (await redis.get(`otp_lock:${email}`)) {
    return next(new ValidationError('Account locked due to multiple failed attempts!. Try again after 30 minutes.'));
  }

  if (await redis.get(`otp_spam_lock:${email}`)) {
    return next(new ValidationError('Too many OTP requests! Try again after 1 hour.'));
  }

  if (await redis.get(`otp_cooldown:${email}`)) {
    return next(new ValidationError('Please wait 1 minute before requesting a new OTP.'));
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

export const trackOtpRequests = async (email: string, next: NextFunction) => {
  const otpRequestKey = `otp_requests_count:${email}`;

  let otpRequest = parseInt(await redis.get(otpRequestKey) || '0');

  if (otpRequest >= 2) {
    await redis.set(`otp_spam_lock:${email}`, 'locked', "EX", 3600); // 1 hour lock
    return next(new ValidationError('Too many OTP requests! Try again after 1 hour.'));
  }

  await redis.set(otpRequestKey, (otpRequest + 1).toString(), "EX", 3600); // Track request for 1 hour
}
