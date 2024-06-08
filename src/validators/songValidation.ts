import { check } from 'express-validator';

export const validateCreateSong = [
  check('genre').notEmpty().withMessage('Genre is required'),
  check('title').notEmpty().withMessage('Title is required'),
  check('recorded_date').optional().isDate().withMessage('Recorded date must be a valid date'),
  check('lyrics').notEmpty().withMessage('Lyrics are required'),
  check('artist').notEmpty().withMessage('Artist ID is required').isMongoId().withMessage('Artist ID must be a valid Mongo ID')
];

