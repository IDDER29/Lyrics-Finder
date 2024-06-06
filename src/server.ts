// src/server.ts

import dotenv from "dotenv";
import app from "./app";
import connectDB from "./config/db";

dotenv.config();
// Connect to MongoDB
connectDB();

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
