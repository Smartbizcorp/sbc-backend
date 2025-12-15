import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import PDFDocument from "pdfkit";
import { authMiddleware } from "../middlewares/auth";

const prisma = new PrismaClient();
const router = Router();

function adminOnly(req: any, res: Response, next: Function) {
  if (req.user?.role !== "ADMIN") {
    return res.status(403).json({ success: false });
  }
  next();
}

router.get(
  "/admin/cgu-proof/:userId/pdf",
  authMiddleware,
  adminOnly,
  async (req: Request, res: Response) => {
    const userId = Number(req.params.userId);

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.acceptCguAt) {
      return res.status(404).json({ success: false, message: "Preuve CGU introuvable" });
    }

    const doc = new PDFDocument({ margin: 50 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=CGU_PROOF_USER_${user.id}.pdf`
    );

    doc.pipe(res);

    doc.fontSize(18).text("Preuve d’acceptation des CGU", { align: "center" });
    doc.moveDown(2);

    doc.fontSize(11);
    doc.text(`Entreprise : Smart Business Corp`);
    doc.text(`Utilisateur : ${user.fullName}`);
    doc.text(`Téléphone : ${user.phone}`);
    if (user.email) doc.text(`Email : ${user.email}`);
    doc.moveDown();

    doc.text(`Date d’acceptation : ${user.acceptCguAt.toISOString()}`);
    doc.text(`Version CGU : ${user.cguVersion}`);
    doc.text(`Hash CGU (SHA-256) :`);
    doc.font("Courier").text(user.cguHash || "N/A");
    doc.font("Helvetica");
    doc.moveDown();

    doc.text(`Adresse IP : ${user.cguIp || "N/A"}`);
    doc.text(`User-Agent :`);
    doc.fontSize(9).text(user.cguUserAgent || "N/A");
    doc.moveDown(2);

    doc.fontSize(10).text(
      "Ce document constitue une preuve légale de l’acceptation des Conditions Générales d’Utilisation conformément au droit OHADA et aux principes de preuve électronique.",
      { align: "justify" }
    );

    doc.end();
  }
);

export default router;
