import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { authMiddleware } from "../middlewares/auth"; // adapte ton chemin réel
import logger from "../logger";
import PDFDocument from "pdfkit";

const prisma = new PrismaClient();
const router = Router();

function requireAdmin(req: any, res: Response, next: any) {
  if (!req.user || req.user.role !== "ADMIN") {
    return res.status(403).json({ success: false, message: "Accès refusé." });
  }
  next();
}

/**
 * GET /api/admin/cgu-acceptances
 * Liste des acceptations CGU (preuve)
 */
router.get(
  "/cgu-acceptances",
  authMiddleware,
  requireAdmin,
  async (req: Request, res: Response) => {
    try {
      const users = await prisma.user.findMany({
        orderBy: [{ acceptCguAt: "desc" }, { createdAt: "desc" }],
        select: {
          id: true,
          fullName: true,
          phone: true,
          email: true,
          acceptCguAt: true,
          cguVersion: true,
          cguHash: true,
          cguIp: true,
          cguUserAgent: true,
          createdAt: true,
        },
      });

      return res.json({ success: true, data: users });
    } catch (err) {
      logger.error({ err }, "[ADMIN] cgu-acceptances error");
      return res.status(500).json({ success: false, message: "Erreur serveur." });
    }
  }
);

/**
 * GET /api/admin/cgu-proof/:userId
 * Retourne un PDF "preuve d'acceptation CGU" (user + hash + IP + horodatage)
 */
router.get(
  "/cgu-proof/:userId",
  authMiddleware,
  requireAdmin,
  async (req: Request, res: Response) => {
    try {
      const userId = Number(req.params.userId);
      if (!userId || Number.isNaN(userId)) {
        return res.status(400).json({ success: false, message: "userId invalide." });
      }

      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          fullName: true,
          phone: true,
          email: true,
          createdAt: true,
          acceptCguAt: true,
          cguVersion: true,
          cguHash: true,
          cguIp: true,
          cguUserAgent: true,
        },
      });

      if (!user) {
        return res.status(404).json({ success: false, message: "Utilisateur introuvable." });
      }

      // Nom fichier
      const safePhone = (user.phone || "user").replace(/[^\d+]/g, "");
      const fileName = `preuve_CGU_user_${user.id}_${safePhone}.pdf`;

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);

      const doc = new PDFDocument({ size: "A4", margin: 50 });

      doc.pipe(res);

      // --- Styles simples ---
      const titleSize = 16;
      const labelSize = 10;
      const valueSize = 11;

      doc.fontSize(titleSize).text("PREUVE D’ACCEPTATION DES CGU", { align: "center" });
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor("#666").text("Smart Business Corp", { align: "center" });
      doc.fillColor("#000");
      doc.moveDown(1);

      const printRow = (label: string, value: any) => {
        doc.fontSize(labelSize).fillColor("#444").text(label);
        doc.fontSize(valueSize).fillColor("#000").text(value ?? "—");
        doc.moveDown(0.6);
      };

      // --- Contenu légal / preuve ---
      printRow("Identifiant utilisateur (User ID)", String(user.id));
      printRow("Nom complet", user.fullName);
      printRow("Téléphone", user.phone);
      printRow("Email", user.email ?? "—");
      printRow("Date création compte", user.createdAt ? new Date(user.createdAt).toLocaleString("fr-FR") : "—");

      doc.moveDown(0.3);
      doc.fontSize(12).text("Preuve d’acceptation", { underline: true });
      doc.moveDown(0.6);

      printRow("Date/heure d’acceptation (acceptCguAt)", user.acceptCguAt ? new Date(user.acceptCguAt).toLocaleString("fr-FR") : "NON ACCEPTÉ");
      printRow("Version CGU (cguVersion)", user.cguVersion ?? "—");
      printRow("Empreinte (hash) CGU (cguHash)", user.cguHash ?? "—");
      printRow("Adresse IP au moment de l’acceptation (cguIp)", user.cguIp ?? "—");
      printRow("User-Agent (cguUserAgent)", user.cguUserAgent ?? "—");

      doc.moveDown(0.8);
      doc.fontSize(9).fillColor("#666").text(
        "Ce document est généré automatiquement par le système Smart Business Corp et constitue une preuve interne de l’acceptation des Conditions Générales d’Utilisation par le client.",
        { align: "justify" }
      );
      doc.fillColor("#000");

      doc.moveDown(1);
      doc.fontSize(9).fillColor("#999").text(
        `Généré le : ${new Date().toLocaleString("fr-FR")}`,
        { align: "right" }
      );

      doc.end();
    } catch (err) {
      logger.error({ err }, "[ADMIN] cgu-proof error");
      return res.status(500).json({ success: false, message: "Erreur serveur." });
    }
  }
);

export default router;
