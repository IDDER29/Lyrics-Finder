import { Request, Response, NextFunction } from "express";
import { ResultWithContextImpl } from "express-validator/lib/chain";
import jwt from "jsonwebtoken";
import { constrainedMemory } from "process";
declare global {
  interface userData {
    id : string,
    isAdmin : boolean
  }
  namespace  Express {
    interface Request {
      user: userData
    }
  }
}

const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  
  if (authHeader) {
    const token = authHeader.split(" ")[1]; // Split "Bearer <token>" to get the token part
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decodedToken) => {
      if (err) {
        res
          .status(401)
          .json({ message: "Unauthorized access. Please authenticate." });
      } else {
        const { id, isAdmin } = decodedToken;
        req.user = { id, isAdmin };

        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ message: "Unauthorized access. Please authenticate." });
  }
};

export { requireAuth };
