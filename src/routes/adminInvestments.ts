// src/routes/adminInvestments.ts
import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { sendPushToUser } from "../services/push";
import logger from "../logger";
import { createNotificationForUser } from "../services/notifications"; // 🔔 import

const prisma = new PrismaClient();
const router = Router();

/* ------------------------------------------------------------------ */
/*                         ZOD / VALIDATIONS                           */
/* ------------------------------------------------------------------ */

// Statuts autorisés côté admin
const ADMIN_INVESTMENT_STATUS = ["PENDING", "ACTIVE", "REJECTED", "CLOSED"] as const;
type AdminInvestmentStatus = (typeof ADMIN_INVESTMENT_STATUS)[number];

const listQuerySchema = z.object({
  status: z
    .string()
    .optional()
    .transform((v) => (v ? v.toUpperCase() : undefined))
    .refine(
      (v) => !v || ADMIN_INVESTMENT_STATUS.includes(v as AdminInvestmentStatus),
      { message: "Statut invalide." }
    ),
  userId: z
    .string()
    .optional()
    .transform((v) => (v ? Number(v) : undefined))
    .refine((v) => v === undefined || (!Number.isNaN(v) && v > 0), {
      message: "userId invalide.",
    }),
  limit: z
    .string()
    .optional()
    .transform((v) => (v ? Number(v) : 50))
    .refine((v) => !Number.isNaN(v) && v > 0 && v <= 200, {
      message: "limit doit être entre 1 et 200.",
    }),
  offset: z
    .string()
    .optional()
    .transform((v) => (v ? Number(v) : 0))
    .refine((v) => !Number.isNaN(v) && v >= 0, {
      message: "offset invalide.",
    }),
});

const updateStatusSchema = z.object({
  status: z
    .string()
    .transform((v) => v.toUpperCase())
    .refine((v) => ADMIN_INVESTMENT_STATUS.includes(v as AdminInvestmentStatus), {
      message: "Statut invalide. Valeurs possibles : PENDING, ACTIVE, REJECTED, CLOSED.",
    }),
});

/* ------------------------------------------------------------------ */
/*                         HELPERS / TRANSITIONS                       */
/* ------------------------------------------------------------------ */

function isValidTransition(
  from: AdminInvestmentStatus,
  to: AdminInvestmentStatus
): boolean {
  if (from === to) return true;

  switch (from) {
    case "PENDING":
      // Après vérification du paiement
      return to === "ACTIVE" || to === "REJECTED";

    case "ACTIVE":
      // En fin de cycle, fermeture manuelle
      return to === "CLOSED";

    case "REJECTED":
      // Une fois rejeté, on ne revient pas en arrière
      return false;

    case "CLOSED":
      // Investissement terminé : plus de changements
      return false;

    default:
      return false;
  }
}

/* ------------------------------------------------------------------ */
/*                  ADMIN – LISTE INVESTISSEMENTS                      */
/*           GET /api/admin/investments?status=&userId=&...           */
/* ------------------------------------------------------------------ */

router.get("/", async (req: Request, res: Response) => {
  try {
    const parsed = listQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      const msg =
        parsed.error.issues[0]?.message ||
        "Paramètres de filtrage invalides.";
      return res.status(400).json({
        success: false,
        message: msg,
      });
    }

    const { status, userId, limit, offset } = parsed.data;

    const where: any = {};
    if (status) where.status = status;
    if (userId) where.userId = userId;

    const [items, totalCount] = await Promise.all([
      prisma.investment.findMany({
        where,
        orderBy: { createdAt: "desc" },
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
              email: true,
            },
          },
          tier: true,
        },
        skip: offset,
        take: limit,
      }),
      prisma.investment.count({ where }),
    ]);

    return res.json({
      success: true,
      data: {
        totalCount,
        limit,
        offset,
        investments: items,
      },
    });
  } catch (err) {
    logger.error({ err }, "Erreur GET /api/admin/investments");
    return res.status(500).json({
      success: false,
      message:
        "Erreur serveur lors de la récupération des investissements.",
    });
  }
});

/* ------------------------------------------------------------------ */
/*                ADMIN – DÉTAIL D’UN INVESTISSEMENT                   */
/*             GET /api/admin/investments/:id                          */
/* ------------------------------------------------------------------ */

router.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: "ID d'investissement invalide.",
      });
    }

    const investment = await prisma.investment.findUnique({
      where: { id },
      include: {
        user: {
          select: {
            id: true,
            fullName: true,
            phone: true,
            email: true,
          },
        },
        tier: true,
      },
    });

    if (!investment) {
      return res.status(404).json({
        success: false,
        message: "Investissement introuvable.",
      });
    }

    return res.json({
      success: true,
      investment,
    });
  } catch (err) {
    logger.error({ err }, "Erreur GET /api/admin/investments/:id");
    return res.status(500).json({
      success: false,
      message:
        "Erreur serveur lors de la récupération de l'investissement.",
    });
  }
});

/* ------------------------------------------------------------------ */
/*       ADMIN – CHANGEMENT DE STATUT D’UN INVESTISSEMENT (SECURE)     */
/*       PATCH /api/admin/investments/:id/status                       */
/* ------------------------------------------------------------------ */

router.patch("/:id/status", async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: "ID d'investissement invalide.",
      });
    }

    const parsed = updateStatusSchema.safeParse(req.body);
    if (!parsed.success) {
      const msg =
        parsed.error.issues[0]?.message ||
        "Données de mise à jour invalides.";
      return res.status(400).json({
        success: false,
        message: msg,
      });
    }

    const newStatus = parsed.data.status as AdminInvestmentStatus;

    const result = await prisma.$transaction(async (tx) => {
      const investment = await tx.investment.findUnique({
        where: { id },
      });

      if (!investment) {
        const error: any = new Error("NOT_FOUND");
        throw error;
      }

      const currentStatus = investment.status as AdminInvestmentStatus;

      if (!ADMIN_INVESTMENT_STATUS.includes(currentStatus)) {
        const error: any = new Error("INVALID_CURRENT_STATUS");
        error.meta = { currentStatus };
        throw error;
      }

      if (!isValidTransition(currentStatus, newStatus)) {
        const error: any = new Error("INVALID_TRANSITION");
        error.meta = { from: currentStatus, to: newStatus };
        throw error;
      }

      // Si le statut est déjà celui demandé -> pas de double traitement
      if (currentStatus === newStatus) {
        return { updated: investment, previousStatus: currentStatus };
      }

      const now = new Date();
      const dataUpdate: any = { status: newStatus };

      // Gestion des dates métier
      if (currentStatus === "PENDING" && newStatus === "ACTIVE") {
        // validation paiement
        dataUpdate.approvedAt = now;
        dataUpdate.rejectedAt = investment.rejectedAt ?? null;
      }

      if (currentStatus === "PENDING" && newStatus === "REJECTED") {
        dataUpdate.rejectedAt = now;
        dataUpdate.approvedAt = investment.approvedAt ?? null;
      }

      if (currentStatus === "ACTIVE" && newStatus === "CLOSED") {
        // pas d'effet financier direct ici : les gains sont gérés par le CRON
        // et les retraits via les endpoints de retrait déjà transactionnels.
      }

      const updated = await tx.investment.update({
        where: { id },
        data: dataUpdate,
      });

      return { updated, previousStatus: currentStatus };
    });

    logger.info(
      {
        investmentId: id,
        oldStatus: result.previousStatus,
        newStatus,
      },
      "[ADMIN] Statut investissement modifié"
    );

        // 🔔 NOTIFICATION UTILISATEUR + PUSH APRÈS MAJ
    const inv = result.updated;
    const amountTxt = inv.principalXOF.toLocaleString("fr-FR");

    if (newStatus === "ACTIVE") {
      // ✅ PUSH vers les devices du user
      await sendPushToUser(inv.userId, {
        title: "Investissement activé 🚀",
        body: `Votre investissement de ${amountTxt} XOF est maintenant en cours.`,
        url: "https://smartbusinesscorp.org/dashboard",
      });

      // 🔔 Notification interne
      await createNotificationForUser({
        userId: inv.userId,
        type: "INVESTMENT_STATUS",
        title: "Investissement activé",
        message: `Votre investissement de ${amountTxt} XOF est maintenant actif.`,
      });
    } else if (newStatus === "REJECTED") {
      await createNotificationForUser({
        userId: inv.userId,
        type: "INVESTMENT_STATUS",
        title: "Investissement refusé",
        message: `Votre demande d'investissement de ${amountTxt} XOF a été refusée.`,
      });

      // (Optionnel) push aussi en cas de refus :
      // await sendPushToUser(inv.userId, {
      //   title: "Investissement refusé ❌",
      //   body: `Votre demande d'investissement de ${amountTxt} XOF a été refusée.`,
      //   url: "https://smartbusinesscorp.org/notifications",
      // });
    }
    // (pour CLOSED on ne crée rien pour l’instant, tu pourras en ajouter une si tu veux)

    return res.json({
      success: true,
      investment: result.updated,
    });

  } catch (err: any) {
    if (err?.message === "NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "Investissement introuvable.",
      });
    }

    if (err?.message === "INVALID_TRANSITION") {
      const meta = err.meta || {};
      return res.status(400).json({
        success: false,
        message: "Transition de statut non autorisée.",
        details: meta,
      });
    }

    if (err?.message === "INVALID_CURRENT_STATUS") {
      return res.status(400).json({
        success: false,
        message:
          "Statut actuel de l'investissement non supporté par le workflow admin.",
      });
    }

    logger.error({ err }, "Erreur PATCH /api/admin/investments/:id/status");
    return res.status(500).json({
      success: false,
      message:
        "Erreur serveur lors de la mise à jour du statut de l'investissement.",
    });
  }
});

export default router;
