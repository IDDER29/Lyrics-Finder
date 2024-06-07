// src/validators/artistValidator.ts
import { body } from 'express-validator';
import {validate} from "../middlewares/validate";

export const validateArtist = [
  body('firstname').notEmpty().withMessage('First name is required'),
  body('lastname').notEmpty().withMessage('Last name is required'),
  body('genre').notEmpty().withMessage('Genre is required'),
  body('born_date').optional().isISO8601().withMessage('Born date must be a valid date'),
  body('born_city').optional().notEmpty().withMessage('Born city is required if provided'),
  body('died_date').optional().isISO8601().withMessage('Died date must be a valid date'),
  validate
];
