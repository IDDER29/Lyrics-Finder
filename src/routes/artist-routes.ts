import Express from "express";
const router = Express.Router();
import {
  addArtist,
  getAllArtist,
  getOneArtist,
  updateArtist,
  deleteArtist,
} from "../controllers/artist-controller";
import { requireAuth } from "../middlewares/auth-middleware";
import { validateArtist } from "../validators/artisteValidation";
import { validate } from "../middlewares/validate";
import upload from "./../config/multer";
import {checkAdmin} from "../middlewares/isAdmin";

router.post(
  "/add-artist",
  requireAuth,
  checkAdmin,
  upload,
  validateArtist,
  addArtist
);
router.route("/").get(requireAuth, getAllArtist);
router.route("/search/:firstName?/:lastName?").get(requireAuth, getOneArtist);
router.route("/:id").put(requireAuth, checkAdmin, updateArtist).delete(requireAuth, checkAdmin, deleteArtist);

export default router;
