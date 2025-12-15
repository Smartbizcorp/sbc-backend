import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Requête authentifiée
 */
export interface AuthRequest extends Request {
  user?: {
    id: number;
    role?: string;
  };
}

/**
 * Middleware d’authentification
 * - JWT stocké en cookie httpOnly (sbc_token)
 * - fallback Authorization: Bearer <token>
 */
export const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    // 1️⃣ Récupération du token
    const token =
      req.cookies?.sbc_token ||
      req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentification requise",
      });
    }

    // 2️⃣ Vérification JWT
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as { id: number };

    if (!decoded?.id) {
      return res.status(401).json({
        success: false,
        message: "Token invalide",
      });
    }

    // 3️⃣ Chargement utilisateur
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        role: true,
        isActive: true,
      },
    });

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: "Utilisateur désactivé ou introuvable",
      });
    }

    // 4️⃣ Injection dans la requête
    req.user = {
      id: user.id,
      role: user.role,
    };

    next();
  } catch (err) {
    console.error("[AUTH ERROR]", err);

    return res.status(401).json({
      success: false,
      message: "Session expirée ou invalide",
    });
  }
};
