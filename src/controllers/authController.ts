import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { sendOtpEmail } from '../utils/email';
import { z } from 'zod';

const prisma = new PrismaClient();

// Input validation schemas
const registerSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.string().email('Invalid email'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(1, 'Password is required'),
});

const otpSchema = z.object({
  userId: z.number().int().positive('Invalid user ID'),
  otpCode: z.string().length(6, 'OTP must be 6 digits'),
});

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password } = registerSchema.parse(req.body);

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ error: 'Email already exists' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        otp: otpCode,
        otpExpiresAt,
        // role: email === 'admin@user.com' ? 'admin' : 'user', // Assigning admin role for testing
      },
    });

    await sendOtpEmail(email, otpCode);
    res.status(201).json({ message: 'User registered, OTP sent', userId: user.id });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: error.errors });
      return;
    }
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
};

export const verifyOtp = async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId, otpCode } = otpSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.isVerified) {
      res.status(400).json({ error: 'User not found or already verified' });
      return;
    }

    if (user.otp !== otpCode || !user.otpExpiresAt || user.otpExpiresAt < new Date()) {
      res.status(400).json({ error: 'Invalid or expired OTP' });
      return;
    }

    await prisma.user.update({
      where: { id: userId },
      data: { isVerified: true, otp: null, otpExpiresAt: null },
    });

    res.json({ message: 'OTP verified, registration complete' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: error.errors });
      return;
    }
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
};

export const resendOtp = async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = z.object({ userId: z.number().int().positive('Invalid user ID') }).parse(req.body);

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.isVerified) {
      res.status(400).json({ error: 'User not found or already verified' });
      return;
    }

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await prisma.user.update({
      where: { id: userId },
      data: { otp: otpCode, otpExpiresAt },
    });

    await sendOtpEmail(user.email, otpCode);
    res.json({ message: 'OTP resent' });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: error.errors });
      return;
    }
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({ error: 'Account not verified' });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', {
      expiresIn: '1h',
    });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ error: error.errors });
      return;
    }
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
};