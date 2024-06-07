import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { User } from "../models/user";
import { sendEmail } from "../services/email-service";
import VerificationCode from "../models/verification-code";
import { body } from 'express-validator';

// Error handling function (already defined above)
function handleError(err: any): Record<string, string> {
  let errors: Record<string, string> = {};

  if (err.code === 11000) {
    errors.email = "This email is already registered";
    return errors;
  }
  if (err.message.includes("User validation failed")) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message;
    });
  }
  return errors;
}

// JWT token creation function
const maxAge = 3 * 24 * 60 * 60;
const createToken = (id, isAdmin) => {
  return jwt.sign({ id, isAdmin }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: maxAge,
  });
};

// Create a new user and send a verification email
const verifyCodeAndCreateUser = async (req: Request, res: Response) => {
  const { email, verificationCode, password, firstname, lastname } = req.body;
  try {
    const record = await VerificationCode.findOne({ email, code: verificationCode });

    if (!record) {
      return res.status(400).json({ message: "Invalid verification code." });
    }

    if (record.expires < new Date()) {
      return res.status(400).json({ message: "Verification code has expired." });
    }

    // Create the user
    const newUser = await User.create({
      email,
      password,
      firstname,
      lastname,
      isVerified: true,
    });

    // Delete the verification record
    await VerificationCode.deleteOne({ email, code: verificationCode });

    const token = createToken(newUser._id, newUser.isAdmin);
    res.status(201).json({ token });
  } catch (error) {
    const errors = handleError(error);
    res.status(400).json({ errors });
  }
};

// Verify the user's email
const generateVerificationCode = async (req: Request, res: Response) => {
  const Body = req.body;
  const user = [Body];
  const email = Body.email;
  try {
    const verificationCode = crypto.randomBytes(4).toString('hex');
    const verificationCodeExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await VerificationCode.create({
      email,
      code: verificationCode,
      expires: verificationCodeExpires,
    });

    const message = `Please verify your email using this code: ${verificationCode}. The code is valid for 1 hour.`;
    const subject = "Email Verification";

    await sendEmail(user, subject, message);

    res.status(200).json({ message: 'Verification email sent. Please verify your email.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to send verification email.' });
  }
};

// Log in the user
const logIn = async (req: Request<{}, {}, { email: string; password: string }>, res: Response) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: "Please verify your email first." });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = createToken(user._id, user.isAdmin);
    res.setHeader("Authorization", token);

    res.status(200).json({ User: user._id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "An unexpected error occurred." });
  }
};

const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const resetToken = crypto.randomBytes(32).toString("hex");

  const hashedToken = jwt.sign(
    { email: email, token: resetToken },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "1h",
    }
  );

  const resetURL = `${req.protocol}://${req.get("host")}/resetPassword/${hashedToken}`;
  const message = `Forgot your password? This is your reset code: ${resetToken}. Click the link to reset your password: ${resetURL}`;

  try {
    const subject = "Your password reset token (valid for 1 hour)";
    await sendEmail(user, subject, message);

    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      message: "There was an error sending the email. Try again later.",
    });
  }
};

const resetPassword = async (req: Request, res: Response) => {
  const { restoredCode, newPassword } = req.body;
  const hashedToken = req.params.token;

  try {
    jwt.verify(hashedToken, process.env.ACCESS_TOKEN_SECRET, async (err, decodedToken) => {
      if (err) {
        res.status(401).json({ message: "Invalid or expired token" });
      } else {
        const { email, token } = decodedToken;
        const userEmail = email;
        const user = await User.findOne({ email: userEmail });

        if (!user) {
          return res.status(400).json({ message: "User not found" });
        }

        if (token === restoredCode) {
          if (newPassword.length < 8) {
            return res.status(400).json({ message: "New password must be at least 8 characters long" });
          }

          const salt = await bcrypt.genSalt();
          const hashedPassword = await bcrypt.hash(newPassword, salt);

          const updatedUser = await User.updateOne({ email: userEmail }, { password: hashedPassword });
          if (updatedUser.modifiedCount === 0) {
            return res.status(500).json({ message: "Failed to update the password" });
          }

          const subject = "Password Reset Successful";
          const message = "Your password has been successfully changed.";
          await sendEmail(user, subject, message);

          res.status(200).json({ message });
        } else {
          res.status(403).json({ message: "You don't have permission to change the password" });
        }
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export { verifyCodeAndCreateUser, logIn, forgotPassword, resetPassword, generateVerificationCode };
