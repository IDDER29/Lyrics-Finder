// src/server.ts

import dotenv from "dotenv";
import app from "./app";
import cron from 'node-cron';
import { sendMailToAllSubs } from "./controllers/newsletter-controller";
dotenv.config();


import connectDB from "./config/db";

// Connect to MongoDB
async function startServer() {
  try {
    await connectDB(); // Ensure the database connection is established before starting the server
    const PORT = process.env.PORT || 3000;
    
    // Schedule task to run every friday at 12:00
    cron.schedule('0 12 * * 5', async () => {
      await sendMailToAllSubs(null, null);
    });

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start the server:", error.message);
  }
}

startServer();
