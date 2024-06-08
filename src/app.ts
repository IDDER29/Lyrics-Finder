import express from "express";
import multer from 'multer';

const upload = multer();
const app = express();


// importe the routes from index.ts
import {
  authRouters,
  songRoutes,
  artistRoute,
  newsletterRoute,
  adminRoutes,
  userRoutes,
} from "./routes/index";

// Middleware de base
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// for parsing multipart/form-data
// app.use(upload.array('image'));

// Routes
app.use("/artist", artistRoute);
app.use("/song", songRoutes);
app.use("/api/admin", adminRoutes);
app.use(authRouters);
app.use("/newsletter", newsletterRoute);
app.use("/user", userRoutes);

// Exemple : app.use('/api/users', userRoutes);

export default app;
