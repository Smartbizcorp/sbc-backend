import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { randomUUID } from "crypto";
import logger from "../logger";

const prisma = new PrismaClient();
const router = Router();

import { JWT_SECRET } from "../config/jwt"; // adapte le chemin relatif;

if (!JWT_SECRET) {
  logger.error("JWT_SECRET manquant dans les variables d'environnement (.env).");
  throw new Error("JWT_SECRET manquant dans les variables d'environnement (.env).");
}

/* -------------------------------------------------------------------------- */
/*                             🔹 Types & Helpers                              */
/* -------------------------------------------------------------------------- */

interface AuthRequest extends Request {
  user?: {
    id: number;
    role: "USER" | "ADMIN";
  };
}

// Mot de passe fort
function isStrongPassword(pwd: string): boolean {
  return pwd.length >= 8 && /[A-Za-z]/.test(pwd) && /\d/.test(pwd);
}

/* -------------------------------------------------------------------------- */
/*                               ✅ Zod schemas                                */
/* -------------------------------------------------------------------------- */

const registerSchema = z.object({
  fullName: z.string().min(3, "Nom trop court."),
  phone: z.string().min(6, "Téléphone invalide."),
  email: z
    .string()
    .email("Email invalide.")
    .optional()
    .or(z.literal("").optional()),
  waveNumber: z.string().min(6, "Numéro Wave invalide."),
  password: z.string().min(8, "Mot de passe trop court (min 8 caractères)."),

  // 🔐 Question + réponse sécurité (ton front les envoie)
  securityQuestion: z.string().min(1, "Veuillez choisir une question de sécurité."),
  securityAnswer: z.string().min(1, "Veuillez renseigner la réponse à la question de sécurité."),

  // ✅ CGU obligatoire
  acceptCgu: z
  .boolean()
  .refine((v) => v === true, {
    message: "Vous devez accepter les Conditions Générales d’Utilisation (CGU).",
  }),
  })

const loginSchema = z.object({
  phone: z.string().min(6, "Téléphone invalide."),
  password: z.string().min(1, "Mot de passe requis."),
});

/* -------------------------------------------------------------------------- */
/*                          🔐 Anti brute-force login                          */
/* -------------------------------------------------------------------------- */

type LoginAttemptInfo = {
  count: number;
  lockedUntil: number | null;
};

const loginAttempts = new Map<string, LoginAttemptInfo>();

const MAX_LOGIN_ATTEMPTS = 5; // après 5 erreurs -> blocage
const LOCK_TIME_MS = 5 * 60 * 1000; // 5 minutes

/* -------------------------------------------------------------------------- */
/*                            ⏱ Rate limiters PRO                             */
/* -------------------------------------------------------------------------- */

export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1h
  max: 20,
  message: {
    success: false,
    message:
      "Trop de tentatives d'inscription. Merci de réessayer dans une heure.",
  },
});

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: {
    success: false,
    message: "Trop de tentatives de connexion. Réessayez plus tard.",
  },
});

/* -------------------------------------------------------------------------- */
/*                            🧑‍💻 REGISTER (POST)                             */
/* -------------------------------------------------------------------------- */

router.post(
  "/register",
  registerLimiter,
  async (req: Request, res: Response) => {
    try {
      const parseResult = registerSchema.safeParse(req.body);

      if (!parseResult.success) {
        const msg =
          parseResult.error.issues[0]?.message ||
          "Données d'inscription invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const {
        fullName,
        phone,
        email,
        waveNumber,
        password,
        securityQuestion,
        securityAnswer,
        acceptCgu, // (Zod garantit que c’est true)
      } = parseResult.data;

      // Vérif force du mot de passe
      if (!isStrongPassword(password)) {
        return res.status(400).json({
          success: false,
          message:
            "Mot de passe trop faible. Minimum 8 caractères avec au moins une lettre et un chiffre.",
        });
      }

      const cleanedEmail =
        email && email.trim() !== "" ? email.trim().toLowerCase() : null;

      // Vérif unicité téléphone
      const existingPhone = await prisma.user.findUnique({ where: { phone } });
      if (existingPhone) {
        return res.status(400).json({
          success: false,
          message: "Ce numéro est déjà utilisé.",
        });
      }

      // Vérif unicité email
      if (cleanedEmail) {
        const existingEmail = await prisma.user.findFirst({
          where: { email: cleanedEmail },
        });
        if (existingEmail) {
          return res.status(400).json({
            success: false,
            message: "Cet email existe déjà.",
          });
        }
      }

      // Hash mot de passe
      const passwordHash = await bcrypt.hash(password, 10);

      // 🔐 Hash réponse de sécurité
      const securityAnswerHash = await bcrypt.hash(securityAnswer.trim(), 10);

      // ✅ Preuve CGU
      const ip =
        ((req.headers["x-forwarded-for"] as string)
          ?.split(",")[0]
          ?.trim()) ||
        req.socket?.remoteAddress ||
        null;

      const userAgent = req.headers["user-agent"] ?? null;
      const CGU_VERSION = process.env.CGU_VERSION ?? "v1.0";

      const user = await prisma.user.create({
        data: {
          fullName,
          phone,
          waveNumber,
          email: cleanedEmail,
          passwordHash,
          isActive: true,
          role: "USER",

          // 🔐 Stockage sécurisé de la question / réponse
          securityQuestion: securityQuestion.trim(),
          securityAnswerHash,

          // ✅ Preuve d'acceptation CGU
          acceptCguAt: new Date(),
          cguVersion: CGU_VERSION,
          cguIp: ip,
          cguUserAgent: userAgent,

          // Optionnel : si tu veux créer un wallet dès l'inscription :
          // wallet: { create: {} },
        },
      });

      logger.info(
        { userId: user.id, phone: user.phone },
        "[AUTH] Nouvel utilisateur inscrit"
      );

      return res.json({ success: true, userId: user.id });
    } catch (err) {
      logger.error({ err }, "[AUTH] Erreur register");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de l'inscription.",
      });
    }
  }
);

/* -------------------------------------------------------------------------- */
/*                             🔐 LOGIN (POST)                                */
/* -------------------------------------------------------------------------- */

router.post("/login", loginLimiter, async (req: Request, res: Response) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);

    if (!parseResult.success) {
      const msg =
        parseResult.error.issues[0]?.message ||
        "Données de connexion invalides.";
      return res.status(400).json({ success: false, message: msg });
    }

    const { phone, password } = parseResult.data;

    // 🔴 Vérifier si ce téléphone est temporairement bloqué
    const attemptInfo = loginAttempts.get(phone);
    const nowTs = Date.now();

    if (attemptInfo?.lockedUntil && nowTs < attemptInfo.lockedUntil) {
      const remainingMs = attemptInfo.lockedUntil - nowTs;
      const remainingMin = Math.ceil(remainingMs / 60000);

      return res.status(429).json({
        success: false,
        message: `Compte temporairement bloqué après plusieurs tentatives échouées. Réessayez dans environ ${remainingMin} minute(s).`,
      });
    }

    const user = await prisma.user.findUnique({ where: { phone } });
    if (!user) {
      // On incrémente le compteur d’échecs même si l’utilisateur n’existe pas
      const current = loginAttempts.get(phone) || {
        count: 0,
        lockedUntil: null,
      };

      current.count += 1;

      if (current.count >= MAX_LOGIN_ATTEMPTS) {
        current.lockedUntil = nowTs + LOCK_TIME_MS;
        current.count = 0;
        loginAttempts.set(phone, current);

        logger.warn(
          { phone },
          "[AUTH] Compte bloqué 5 minutes après trop de tentatives échouées (user inexistant)."
        );

        return res.status(429).json({
          success: false,
          message:
            "Compte temporairement bloqué après plusieurs tentatives échouées. Réessayez dans quelques minutes.",
        });
      }

      loginAttempts.set(phone, current);

      return res.status(401).json({
        success: false,
        message: "Identifiants incorrects.",
      });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      const current = loginAttempts.get(phone) || {
        count: 0,
        lockedUntil: null,
      };

      current.count += 1;

      if (current.count >= MAX_LOGIN_ATTEMPTS) {
        current.lockedUntil = nowTs + LOCK_TIME_MS;
        current.count = 0;
        loginAttempts.set(phone, current);

        logger.warn(
          { phone, userId: user.id },
          "[AUTH] Compte bloqué 5 minutes après trop de tentatives échouées (mauvais mot de passe)."
        );

        return res.status(429).json({
          success: false,
          message:
            "Compte temporairement bloqué après plusieurs tentatives échouées. Réessayez dans quelques minutes.",
        });
      }

      loginAttempts.set(phone, current);

      return res.status(401).json({
        success: false,
        message: "Identifiants incorrects.",
      });
    }

    // ✅ Login OK → reset des tentatives
    if (loginAttempts.has(phone)) {
      loginAttempts.delete(phone);
    }

    // 🆔 Générer un identifiant unique de session (jti)
    const jti = randomUUID();

    // IP simplifiée (tu peux l'améliorer en hash)
    const ip =
      (req.headers["x-forwarded-for"] as string) ||
      req.socket.remoteAddress ||
      "unknown";

    // Création de la session en base
    await prisma.session.create({
      data: {
        jti,
        userId: user.id,
        userAgent: req.headers["user-agent"] || null,
        ipHash: ip,
      },
    });

    // Token signé avec jti (même format que ton authMiddleware)
    const token = jwt.sign(
      { userId: user.id, role: user.role as "USER" | "ADMIN", jti },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // 🥠 Cookie httpOnly sbc_token
    res.cookie("sbc_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    logger.info(
      { userId: user.id, phone: user.phone },
      "[AUTH] Connexion réussie"
    );

    return res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.fullName,
        phone: user.phone,
        role: user.role,
      },
    });
  } catch (err) {
    logger.error({ err }, "[AUTH] Erreur login");
    return res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la connexion.",
    });
  }
});

export default router;
