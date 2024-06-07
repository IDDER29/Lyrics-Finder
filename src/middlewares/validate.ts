import { Request, Response, NextFunction } from "express";
const { body, validationResult } = require("express-validator");

export const validate = (req: Request, res: Response, next: NextFunction) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const formattedErrors = errors
      .array()
      .map(({ path, msg }) => ({ path, msg }));
    return res.status(400).json(formattedErrors);
  }
  next();
};
