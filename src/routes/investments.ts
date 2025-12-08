// src/routes/investments.ts
import { Router, Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";

const router = Router();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET!;

/* --------------------------------------------------- */
/*              🔧 EXTENSION DU TYPE REQUEST           */
/* --------------------------------------------------- */
interface AuthRequest extends Request {
  user?: { id: number };
}

/* --------------------------------------------------- */
/*                   🔐 MIDDLEWARE AUTH                 */
/* --------------------------------------------------- */
function auth(req: AuthRequest, res: Response, next: NextFunction) {
  const token =
    req.cookies?.sbc_token ||
    (req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.substring(7)
      : null);

  if (!token)
    return res.status(401).json({ success: false, message: "Non authentifié." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = { id: decoded.userId };
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Token invalide." });
  }
}

/* ---------------------------------------------------------- */
/*   1️⃣   CLIENT — LISTE DE SES INVESTISSEMENTS               */
/* ---------------------------------------------------------- */

router.get("/me", auth, async (req: AuthRequest, res: Response) => {
  try {
    const inv = await prisma.investment.findMany({
      where: { userId: req.user!.id },
      orderBy: { createdAt: "desc" },
    });

    return res.json({ success: true, investments: inv });
  } catch (error) {
    console.error("Erreur GET /api/investments/me :", error);
    return res.status(500).json({
      success: false,
      message: "Erreur interne lors du chargement des investissements.",
    });
  }
});

export default router;
