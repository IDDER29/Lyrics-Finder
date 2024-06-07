import express from "express";
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

// Routes
app.use("/artist", artistRoute);
app.use("/song", songRoutes);
app.use("/api/admin", adminRoutes);
app.use(authRouters);
app.use("/newsletter", newsletterRoute);
app.use("/user", userRoutes);

// Exemple : app.use('/api/users', userRoutes);

export default app;
