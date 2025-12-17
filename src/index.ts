import {
  getVapidPublicKey,
  saveSubscriptionForUser,
  sendPushToUser,
} from "./services/push";
import i18nTranslateRouter from "./routes/i18nTranslate";
import adminCguRouter from "./routes/adminCgu";
import adminCguPdfRouter from "./routes/adminCguPdf";
import adminInvestmentsRouter from "./routes/adminInvestments";
import * as Sentry from "@sentry/node";
import { createNotificationForUser, NotificationType } from "./services/notifications";
import { nodeProfilingIntegration } from "@sentry/profiling-node";
import { randomUUID, createHash } from "crypto";
import cookieParser from "cookie-parser";
import "dotenv/config";
import { z } from "zod";
import express, {
  Request,
  Response,
  NextFunction,
  CookieOptions,
} from "express";
import cors from "cors";
import cron from "node-cron";
import helmet from "helmet";
import { JWT_SECRET } from "./config/jwt"; // adapte le chemin relatif
import rateLimit from "express-rate-limit";
import { PrismaClient } from "@prisma/client";

import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import logger from "./logger";
import {
  cloudflareGuard,
  cloudflareRateLimiter,
} from "./middlewares/cloudflare";

// ✅ SMS + WhatsApp
import { sendSms, notifyAdminSms } from "./services/sms";
import { sendWhatsAppText, notifyAdminWhatsApp } from "./services/whatsapp";

/* ------------------------------------------------------------------ */
/*                             ENUM SUPPORT                           */
/* ------------------------------------------------------------------ */

// Enums gérés côté TypeScript (les colonnes sont des String en DB)
export enum SupportStatus {
  OPEN = "OPEN",
  NEEDS_ADMIN = "NEEDS_ADMIN",
  CLOSED = "CLOSED",
}

export enum SupportSender {
  USER = "USER",
  ADMIN = "ADMIN",
  BOT = "BOT",
}

/* ------------------------------------------------------------------ */
/*                             APP & PRISMA                            */
/* ------------------------------------------------------------------ */

const app = express();
const prisma = new PrismaClient();

const PORT = process.env.PORT || 4000;
const isProd = process.env.NODE_ENV === "production";

if (!JWT_SECRET) {
  logger.error("JWT_SECRET manquant dans les variables d'environnement (.env).");
  throw new Error(
    "JWT_SECRET manquant dans les variables d'environnement (.env)."
  );
}

/* ------------------------------------------------------------------ */
/*                         CONFIG COOKIES SÉCURISÉS                    */
/* ------------------------------------------------------------------ */

const COOKIE_NAME = "sbc_token";

// On typpe explicitement le SameSite pour qu'il soit compatible avec Express
const sameSiteOption: CookieOptions["sameSite"] = isProd ? "none" : "lax";

const BASE_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: isProd,      // en prod, toujours HTTPS
  sameSite: sameSiteOption, // ✅ accepte le cross-site en prod
};

const AUTH_COOKIE_OPTIONS: CookieOptions = {
  ...BASE_COOKIE_OPTIONS,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
};

/* ------------------------------------------------------------------ */
/*                              HELPERS IP                             */
/* ------------------------------------------------------------------ */

function getClientIp(req: Request): string {
  const cfIp = (req.headers["cf-connecting-ip"] as string) || "";
  if (cfIp) return cfIp.trim();

  const xff = (req.headers["x-forwarded-for"] as string) || "";
  if (xff) return xff.split(",")[0].trim();

  return (req.socket.remoteAddress as string) || "unknown";
}

function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("hex");
}

/* ------------------------------------------------------------------ */
/*                   ANTI-XSS / SANITIZATION GLOBALE                   */
/* ------------------------------------------------------------------ */

function sanitizeString(value: string): string {
  let v = value;

  // Retirer les balises <script> et javascript:
  v = v.replace(/<\s*script/gi, "");
  v = v.replace(/<\s*\/\s*script\s*>/gi, "");
  v = v.replace(/javascript:/gi, "");

  // On peut aussi limiter certains attributs on*
  v = v.replace(/\son\w+="[^"]*"/gi, "");
  v = v.replace(/\son\w+='[^']*'/gi, "");

  return v;
}

function deepSanitize(input: any): any {
  if (typeof input === "string") {
    return sanitizeString(input);
  }
  if (Array.isArray(input)) {
    return input.map((item) => deepSanitize(item));
  }
  if (input && typeof input === "object") {
    const copy: any = Array.isArray(input) ? [] : { ...input };
    for (const key of Object.keys(copy)) {
      copy[key] = deepSanitize(copy[key]);
    }
    return copy;
  }
  return input;
}

const sanitizeMiddleware = (req: Request, _res: Response, next: NextFunction) => {
  if (req.body) req.body = deepSanitize(req.body);
  if (req.query) req.query = deepSanitize(req.query);
  if (req.params) req.params = deepSanitize(req.params);
  next();
};

/* ------------------------------------------------------------------ */
/*                      ESCAPE HTML (pour les emails)                  */
/* ------------------------------------------------------------------ */

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ------------------------------------------------------------------ */
/*                         ZOD SCHEMAS & VALIDATION                    */
/* ------------------------------------------------------------------ */

// ✅ Un seul regex pour tous les numéros SN
const SENEGAL_PHONE_REGEX = /^\+221\d{9}$/;
const SENEGAL_PHONE_MESSAGE =
  "Nous n'acceptons pour le moment que les numéros du Sénégal au format +221XXXXXXXXX.";

const registerSchema = z.object({
  fullName: z.string().min(3, "Nom trop court."),
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  email: z
    .string()
    .email("Email invalide.")
    .optional()
    .or(z.literal("").optional()),
  waveNumber: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  password: z.string().min(8, "Mot de passe trop court (min 8 caractères)."),

  // 🔐 Nouveaux champs OBLIGATOIRES
  securityQuestion: z.string().min(5, "Question de sécurité trop courte."),
  securityAnswer: z.string().min(1, "Réponse de sécurité trop courte."),
});

// 🔐 FORGOT PASSWORD SCHEMAS
const forgotPasswordStartSchema = z.object({
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
});

const forgotPasswordVerifySchema = z.object({
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  answer: z.string().min(1, "Réponse de sécurité obligatoire."),
});

const forgotPasswordResetSchema = z.object({
  resetToken: z.string().min(1, "Token de réinitialisation manquant."),
  newPassword: z.string().min(8, "Le nouveau mot de passe est trop court."),
});

const loginSchema = z.object({
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  password: z.string().min(1, "Mot de passe requis."),
});

const withdrawalSchema = z.object({
  amount: z
    .number()
    .int("Le montant doit être un entier.")
    .positive("Le montant doit être strictement positif."),
  waveNumber: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  note: z.string().max(1000).optional(),
});

const investmentSchema = z.object({
  amountXOF: z
    .number()
    .int("Le montant doit être un entier.")
    .positive("Le montant doit être strictement positif."),
});

const supportChatSchema = z.object({
  message: z.string().min(2, "Message trop court."),
  history: z
    .array(
      z.object({
        sender: z.string(),
        text: z.string(),
      })
    )
    .optional(),
  conversationId: z.number().int().optional(), // pour continuer une conversation existante
});

const faqQuestionSchema = z.object({
  name: z.string().min(2, "Nom trop court."),
  phone: z.string().min(6, "Téléphone invalide."),
  email: z.string().email("Email invalide."),
  question: z.string().min(10, "Votre question est trop courte."),
});

const profileUpdateSchema = z.object({
  email: z
    .string()
    .email("Email invalide.")
    .optional()
    .or(z.literal("").optional()),
  waveNumber: z.string().min(6, "Numéro Wave invalide.").optional(),
  orangeMoneyNumber: z
    .string()
    .min(6, "Numéro Orange Money invalide.")
    .optional()
    .or(z.literal("").optional()),
  country: z
    .string()
    .min(2, "Pays invalide.")
    .optional()
    .or(z.literal("").optional()),
  city: z
    .string()
    .min(2, "Ville invalide.")
    .optional()
    .or(z.literal("").optional()),
  birthDate: z
    .string()
    .datetime()
    .optional()
    .or(z.literal("").optional()),
  idType: z
    .string()
    .min(2, "Type de pièce invalide.")
    .optional()
    .or(z.literal("").optional()),
  idNumber: z
    .string()
    .min(2, "Numéro de pièce invalide.")
    .optional()
    .or(z.literal("").optional()),
  securityQuestion: z
    .string()
    .min(5, "Question trop courte.")
    .optional()
    .or(z.literal("").optional()),
  securityAnswer: z
    .string()
    .min(1, "Réponse trop courte.")
    .optional()
    .or(z.literal("").optional()),
});

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, "Mot de passe actuel requis."),
  newPassword: z.string().min(8, "Le nouveau mot de passe est trop court."),
});

const passwordResetStartSchema = z.object({
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
});

const passwordResetConfirmSchema = z.object({
  phone: z.string().regex(SENEGAL_PHONE_REGEX, SENEGAL_PHONE_MESSAGE),
  securityAnswer: z.string().min(1, "Réponse de sécurité requise."),
  newPassword: z.string().min(8, "Mot de passe trop court (min 8 caractères)."),
});

/* ------------------------------------------------------------------ */
/*                         MAIL (BREVO SMTP)                           */
/* ------------------------------------------------------------------ */

const {
  BREVO_SMTP_HOST,
  BREVO_SMTP_PORT,
  BREVO_SMTP_LOGIN,
  BREVO_SMTP_PASSWORD,
  EMAIL_FROM,
} = process.env;

export const isEmailEnabled =
  !!BREVO_SMTP_HOST &&
  !!BREVO_SMTP_LOGIN &&
  !!BREVO_SMTP_PASSWORD &&
  !!EMAIL_FROM;

if (!isEmailEnabled) {
  logger.error(
    "❌ Config SMTP Brevo incomplète : vérifier BREVO_SMTP_HOST / BREVO_SMTP_PORT / BREVO_SMTP_LOGIN / BREVO_SMTP_PASSWORD / EMAIL_FROM."
  );
} else {
  logger.info("✅ Config mail (Brevo SMTP) chargée.");
}

const transporter = nodemailer.createTransport({
  host: BREVO_SMTP_HOST,
  port: Number(BREVO_SMTP_PORT) || 587,
  secure: false, // STARTTLS automatique sur 587
  auth: {
    user: BREVO_SMTP_LOGIN,
    pass: BREVO_SMTP_PASSWORD,
  },
});


/* ------------------------------------------------------------------ */
/*                            SENTRY INIT                              */
/* ------------------------------------------------------------------ */

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || "development",
  integrations: [nodeProfilingIntegration()],
  tracesSampleRate: 1.0,
  profilesSampleRate: 1.0,
});

/* ------------------------------------------------------------------ */
/*                          CORS / SECURITY (UPDATED)                 */
/* ------------------------------------------------------------------ */

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:4001",

  // PROD
  "https://smartbusinesscorp.org",
  "https://www.smartbusinesscorp.org",
  "https://app.smartbusinesscorp.org",

  // Vercel preview / prod
  "https://sbc-frontend.vercel.app",
  "https://sbc-frontend-git-main-smart-business-corp.vercel.app",
];

const corsOptions: cors.CorsOptions = {
  origin(origin, callback) {
    // Autoriser Postman / curl / mobile / SSR
    if (!origin) return callback(null, true);

    // Autoriser toutes les previews Vercel automatiquement
    if (origin.endsWith(".vercel.app")) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(
      new Error(`CORS bloqué pour l'origine : ${origin}`)
    );
  },

  credentials: true, // 🔑 OBLIGATOIRE pour cookies / sessions
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-Request-Id",
  ],
  exposedHeaders: ["X-Request-Id"],
  optionsSuccessStatus: 204,
};

// ⚠️ IMPORTANT : AVANT toute route
app.set("trust proxy", 1);
app.use(cors(corsOptions));

// ⚠️ Préflight explicite (OBLIGATOIRE pour POST cross-origin)
app.options("*", cors(corsOptions));


/* ------------------------------------------------------------------ */
/*                         MIDDLEWARES GLOBAUX                         */
/* ------------------------------------------------------------------ */

// ID de requête pour le traçage
app.use((req: Request, res: Response, next: NextFunction) => {
  const requestId = randomUUID();
  (req as any).requestId = requestId;
  res.setHeader("X-Request-Id", requestId);

  logger.info(
    {
      requestId,
      method: req.method,
      path: req.path,
    },
    "Requête entrante"
  );

  next();
});

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use("/api", i18nTranslateRouter);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https:"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", ...allowedOrigins],
        frameAncestors: ["'self'"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// 🔐 HSTS production (anti downgrade HTTPS)
if (isProd) {
  app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 an
      includeSubDomains: true,
      preload: true,
    })
  );
}

app.use("/api/admin", adminCguRouter);
app.use("/api", adminCguPdfRouter);
app.use(express.json());
app.use(cookieParser());

// 🔐 Anti-XSS & sanitization globale
app.use(sanitizeMiddleware);

// 🌩️ Cloudflare guard + rate-limit dédié
app.use(cloudflareGuard);
app.use(cloudflareRateLimiter);

/* ------------------------------------------------------------------ */
/*                             TYPES REQ                               */
/* ------------------------------------------------------------------ */

interface AuthRequest extends Request {
  user?: {
    id: number;
    role: "USER" | "ADMIN";
  };
  cookies: Record<string, string>;
}

/* ------------------------------------------------------------------ */
/*                          RATE LIMITERS                              */
/* ------------------------------------------------------------------ */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Trop de tentatives de connexion. Réessayez plus tard.",
  },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      "Trop de tentatives d'inscription. Merci de réessayer dans une heure.",
  },
});

// 🔐 Protection brute-force : suivi des tentatives de connexion par téléphone
type LoginAttemptInfo = {
  count: number;
  lockedUntil: number | null;
};

const loginAttempts = new Map<string, LoginAttemptInfo>();

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME_MS = 5 * 60 * 1000;

// 🔐 Rate limit pour la réponse à la question secrète (mot de passe oublié)
type SecurityAnswerAttemptInfo = {
  count: number;
  lockedUntil: number | null;
};

const securityAnswerAttempts = new Map<string, SecurityAnswerAttemptInfo>();

const MAX_SECURITY_ANSWER_ATTEMPTS = 5;
const SECURITY_ANSWER_LOCK_TIME_MS = 10 * 60 * 1000; // 10 min

// Rate limiter GLOBAL sur /api/*
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      "Trop de requêtes depuis cette adresse IP. Merci de réessayer un peu plus tard.",
  },
});

app.use("/api", apiLimiter);

/* ------------------------------------------------------------------ */
/*                        AUTH / ADMIN MIDDLEWARE                      */
/* ------------------------------------------------------------------ */

const SESSION_ROTATION_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h

const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  // ❌ Suppression totale de Bearer : on ne lit QUE le cookie
  const token = req.cookies?.[COOKIE_NAME];

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Non authentifié." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET!) as {
      userId: number;
      role: "USER" | "ADMIN";
      jti?: string;
      iat?: number;
    };

    if (!payload.jti) {
      return res.status(401).json({
        success: false,
        message: "Session invalide (identifiant de session manquant).",
      });
    }

    const session = await prisma.session.findUnique({
      where: { jti: payload.jti },
    });

    if (!session || session.revokedAt) {
      res.clearCookie(COOKIE_NAME, BASE_COOKIE_OPTIONS);
      return res.status(401).json({
        success: false,
        message: "Session expirée ou révoquée. Veuillez vous reconnecter.",
      });
    }

    // 🔐 Validation IP + hash
    const clientIp = getClientIp(req);
    const currentIpHash = hashIp(clientIp);

    let ipMatch = false;

    if (!session.ipHash) {
      ipMatch = true; // première fois
    } else if (session.ipHash.length < 50) {
      // ancien format : IP en clair
      if (session.ipHash === clientIp) {
        ipMatch = true;
      }
    } else {
      if (session.ipHash === currentIpHash) {
        ipMatch = true;
      }
    }

    if (!ipMatch) {
      // suspicion de hijack → on révoque la session et on force un relog
      await prisma.session.updateMany({
        where: { jti: session.jti, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      res.clearCookie(COOKIE_NAME, BASE_COOKIE_OPTIONS);

      logger.warn(
        {
          userId: session.userId,
          oldIpHash: session.ipHash,
          newIpHash: currentIpHash,
        },
        "Suspicion de session hijacking (IP mismatch)"
      );

      return res.status(401).json({
        success: false,
        message:
          "Votre session n'est plus valide. Merci de vous reconnecter.",
      });
    }

    const now = new Date();
    let activeJti = session.jti;
    let effectiveSession = session;

    // Mise à jour ipHash vers le format hashé si besoin
    if (session.ipHash !== currentIpHash) {
      effectiveSession = await prisma.session.update({
        where: { jti: session.jti },
        data: {
          ipHash: currentIpHash,
          lastSeenAt: now,
        },
      });
    } else {
      await prisma.session.update({
        where: { jti: session.jti },
        data: { lastSeenAt: now },
      });
    }

    // 🔄 Rotation automatique de session si le token est trop ancien
    let shouldRotate = false;
    if (typeof payload.iat === "number") {
      const issuedAtMs = payload.iat * 1000;
      if (Date.now() - issuedAtMs > SESSION_ROTATION_INTERVAL_MS) {
        shouldRotate = true;
      }
    }

    if (shouldRotate) {
      const newJti = randomUUID();

      const newSession = await prisma.$transaction(async (tx) => {
        await tx.session.updateMany({
          where: { jti: effectiveSession.jti, revokedAt: null },
          data: { revokedAt: now },
        });

        return tx.session.create({
          data: {
            jti: newJti,
            userId: effectiveSession.userId,
            userAgent: effectiveSession.userAgent,
            ipHash: currentIpHash,
            lastSeenAt: now,
          },
        });
      });

      const newToken = jwt.sign(
        { userId: payload.userId, role: payload.role, jti: newJti },
        JWT_SECRET!,
        { expiresIn: "7d" }
      );

      res.cookie(COOKIE_NAME, newToken, AUTH_COOKIE_OPTIONS);

      activeJti = newSession.jti;
      effectiveSession = newSession;

      logger.info(
        {
          userId: effectiveSession.userId,
          oldJti: session.jti,
          newJti,
        },
        "Session JWT automatiquement rotatée"
      );
    }

    req.user = { id: payload.userId, role: payload.role };
    (req as any).sessionJti = activeJti;

    next();
  } catch (err) {
    logger.warn({ err }, "authMiddleware: token invalide");
    res.clearCookie(COOKIE_NAME, BASE_COOKIE_OPTIONS);
    return res
      .status(401)
      .json({ success: false, message: "Token invalide." });
  }
};

const adminMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  if (!req.user || req.user.role !== "ADMIN")
    return res.status(403).json({
      success: false,
      message: "Accès réservé à l'administration.",
    });
  next();
};

/* ------------------------------------------------------------------ */
/*                         HELPERS / UTILITIES                         */
/* ------------------------------------------------------------------ */

function isStrongPassword(pwd: string): boolean {
  return pwd.length >= 8 && /[A-Za-z]/.test(pwd) && /\d/.test(pwd);
}

// taux pour doubler en 90 jours
function getDailyRateForPrincipal(): number {
  return 1 / 90;
}

/* ------------------------------------------------------------------ */
/*                              CRON JOB                               */
/* ------------------------------------------------------------------ */

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const MAX_DURATION_DAYS = 90;
const MAX_DURATION_MS = MAX_DURATION_DAYS * ONE_DAY_MS;

cron.schedule("*/10 * * * *", async () => {
  const now = new Date();
  logger.info({ now }, "[CRON] Vérification des gains…");

  try {
    const investments = await prisma.investment.findMany({
      where: { status: "ACTIVE" },
    });

    for (const inv of investments) {
      const investmentAgeMs = now.getTime() - inv.createdAt.getTime();

      /* ============================================================ */
      /*              🛑 CLOTURE ABSOLUE À 90 JOURS                    */
      /* ============================================================ */
      if (investmentAgeMs >= MAX_DURATION_MS) {
        await prisma.$transaction(async (tx) => {
          const fresh = await tx.investment.findUnique({
            where: { id: inv.id },
            select: { id: true, userId: true, status: true },
          });

          if (!fresh || fresh.status !== "ACTIVE") return;

          // 1️⃣ Clôture définitive
          await tx.investment.update({
            where: { id: fresh.id },
            data: {
              status: "CLOSED",
              endDate: now,
            },
          });

          // 2️⃣ Notification UNIQUE J+90
          await tx.notification.create({
            data: {
              userId: fresh.userId,
              type: "INVESTMENT_MATURED",
              title: "Investissement arrivé à échéance",
              message: "Votre investissement est arrivé à échéance.",
            },
          });
        });

        logger.info(
          { investmentId: inv.id, userId: inv.userId },
          "[CRON] Investissement clôturé + notification (J+90)"
        );

        continue;
      }

      /* ============================================================ */
      /*                   ⏱ CALCUL DES GAINS                         */
      /* ============================================================ */

      const last = inv.lastGainAt ?? inv.createdAt;
      const diffMs = now.getTime() - last.getTime();

      // Crédit uniquement si ≥ 1 jour
      if (diffMs < ONE_DAY_MS) continue;

      const daysToCredit = Math.floor(diffMs / ONE_DAY_MS);
      if (daysToCredit <= 0) continue;

      // Limite stricte jusqu'à 90 jours
      const daysSinceStart = Math.floor(
        (last.getTime() - inv.createdAt.getTime()) / ONE_DAY_MS
      );

      const remainingDays = MAX_DURATION_DAYS - daysSinceStart;
      if (remainingDays <= 0) continue;

      const effectiveDays = Math.min(daysToCredit, remainingDays);

      const rate = getDailyRateForPrincipal();
      const gainPerDay = Math.round(inv.principalXOF * rate);
      const totalGain = gainPerDay * effectiveDays;

      await prisma.$transaction(async (tx) => {
        const freshInv = await tx.investment.findUnique({
          where: { id: inv.id },
        });

        if (!freshInv || freshInv.status !== "ACTIVE") return;

        const lastGainAt = freshInv.lastGainAt ?? freshInv.createdAt;
        const diffMsInner = now.getTime() - lastGainAt.getTime();
        if (diffMsInner < ONE_DAY_MS) return;

        const daysToCreditInner = Math.floor(diffMsInner / ONE_DAY_MS);
        if (daysToCreditInner <= 0) return;

        const daysSinceStartInner = Math.floor(
          (lastGainAt.getTime() - freshInv.createdAt.getTime()) / ONE_DAY_MS
        );

        const remainingDaysInner = MAX_DURATION_DAYS - daysSinceStartInner;
        if (remainingDaysInner <= 0) return;

        const effectiveDaysInner = Math.min(
          daysToCreditInner,
          remainingDaysInner
        );

        const gainPerDayInner = Math.round(
          freshInv.principalXOF * rate
        );
        const totalGainInner =
          gainPerDayInner * effectiveDaysInner;

        const newLastGainAt = new Date(
          lastGainAt.getTime() +
            effectiveDaysInner * ONE_DAY_MS
        );

        // 1️⃣ Investment
        await tx.investment.update({
          where: { id: freshInv.id },
          data: {
            accruedGainXOF:
              freshInv.accruedGainXOF + totalGainInner,
            lastGainAt: newLastGainAt,
          },
        });

        // 2️⃣ Wallet
        await tx.wallet.upsert({
          where: { userId: freshInv.userId },
          update: { balance: { increment: totalGainInner } },
          create: {
            userId: freshInv.userId,
            balance: totalGainInner,
          },
        });

        // 3️⃣ Ledger
        await tx.ledgerEntry.create({
          data: {
            userId: freshInv.userId,
            type: "CREDIT",
            amount: totalGainInner,
            source: "CRON_GAIN",
            reference: `INVESTMENT#${freshInv.id}`,
          },
        });

        logger.info(
          {
            investmentId: freshInv.id,
            userId: freshInv.userId,
            creditedDays: effectiveDaysInner,
            totalGain: totalGainInner,
          },
          "[CRON] Gains crédités (limités à 90 jours)"
        );
      });
    }
  } catch (err) {
    logger.error(
      { err },
      "[CRON] Erreur lors de la mise à jour des gains"
    );
  }
});

/* ------------------------------------------------------------------ */
/*                                 FAQ                                 */
/* ------------------------------------------------------------------ */

app.post("/api/faq-question", async (req: Request, res: Response) => {
  try {
    const parseResult = faqQuestionSchema.safeParse(req.body);

    if (!parseResult.success) {
      const msg =
        parseResult.error.issues[0]?.message ||
        "Données invalides envoyées au serveur.";
      return res.status(400).json({
        success: false,
        message: msg,
      });
    }

    const { name, phone, email, question } = parseResult.data;

    if (isEmailEnabled) {
  const mailOptions = {
    from: EMAIL_FROM,
    replyTo: email,
    to: "contact@smartbusinesscorp.org",
    subject: "Nouvelle question FAQ — Smart Business Corp",
    html: `
      <h3>Nouvelle question soumise depuis la FAQ</h3>
      <p><strong>Nom :</strong> ${escapeHtml(name)}</p>
      <p><strong>Téléphone :</strong> ${escapeHtml(phone)}</p>
      <p><strong>Email :</strong> ${escapeHtml(email)}</p>
      <p><strong>Question :</strong></p>
      <p>${escapeHtml(question)}</p>
    `,
  };

  await transporter.sendMail(mailOptions);
}

    return res.json({
      success: true,
      message: "Votre question a été envoyée. Merci !",
    });
  } catch (err) {
    console.error("❌ Erreur envoi mail FAQ :", err);
    return res.status(500).json({
      success: false,
      message: "Impossible d'envoyer votre question. Réessayez plus tard.",
    });
  }
});

/* ------------------------------------------------------------------ */
/*                          SUPPORT / CHATBOX                          */
/* ------------------------------------------------------------------ */

app.post(
  "/api/support/chat",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const parsed = supportChatSchema.safeParse(req.body);

      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message || "Message invalide.";
        return res.status(400).json({
          ok: false,
          success: false,
          message: msg,
        });
      }

      const { message, history, conversationId } = parsed.data;
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({ where: { id: userId } });

      // 1️⃣ On trouve (ou crée) la conversation
      let conversation =
        conversationId != null
          ? await prisma.supportConversation.findFirst({
              where: { id: conversationId, userId },
            })
          : null;

      if (!conversation) {
        conversation = await prisma.supportConversation.create({
          data: {
            userId,
            status: SupportStatus.OPEN,
          },
        });
      }

      // 2️⃣ On enregistre le message utilisateur (UNE SEULE FOIS)
      await prisma.supportMessage.create({
        data: {
          conversationId: conversation.id,
          sender: SupportSender.USER,
          text: message,
          seenByAdmin: false,
          seenByUser: true,
        },
      });

      const lower = message.toLowerCase();

      const needAdmin =
        lower.includes("bug") ||
        lower.includes("erreur") ||
        lower.includes("bloqué") ||
        lower.includes("bloquee") ||
        lower.includes("paiement") ||
        lower.includes("wave") ||
        lower.includes("retrait") ||
        lower.includes("remboursement");

      // 3️⃣ Si besoin d’admin → escalade directe
      if (needAdmin) {
        await prisma.supportConversation.update({
          where: { id: conversation.id },
          data: { status: SupportStatus.NEEDS_ADMIN },
        });

        // 🔔 Notifs admin (mail + SMS + WhatsApp)
        try {
          if (isEmailEnabled) {
  await transporter.sendMail({
    from: EMAIL_FROM,
    to: "contact@smartbusinesscorp.org",
    subject: "Nouveau message assistance - nécessite un admin",
    html: `
      <h3>Message support à traiter</h3>
      <p><strong>Conversation #${conversation.id}</strong></p>
      <p><strong>Utilisateur :</strong> ${escapeHtml(
        user?.fullName || "Inconnu"
      )} (#${userId})</p>
      <p><strong>Téléphone :</strong> ${escapeHtml(user?.phone || "-")}</p>
      <p><strong>Email :</strong> ${escapeHtml(user?.email || "-")}</p>
      <p><strong>Message :</strong></p>
      <p>${escapeHtml(message)}</p>
      ${
        history && history.length
          ? `<hr/><p><strong>Historique récent :</strong></p><ul>${history
              .slice(-5)
              .map(
                (h) =>
                  `<li>[${escapeHtml(h.sender)}] ${escapeHtml(h.text)}</li>`
              )
              .join("")}</ul>`
          : ""
      }
    `,
  });
}

          await notifyAdminSms(
            `Support: msg user #${userId}, conv #${conversation.id}`
          );
          await notifyAdminWhatsApp(
            `Support Smart Business Corp\n\nMsg nécessitant admin.\nUser #${userId} (${user?.fullName || "-"})\nConv #${conversation.id}`
          );
        } catch (notifErr) {
          console.error("Erreur notif support admin:", notifErr);
        }

        return res.json({
          ok: true,
          success: true,
          type: "admin_pending",
          conversationId: conversation.id,
          message:
            "Votre demande a été transmise à un administrateur. Vous recevrez une réponse personnalisée dès que possible.",
        });
      }

      // 3bis️⃣ Vérifier si un admin est déjà intervenu dans cette conversation
      const adminAlreadyReplied = await prisma.supportMessage.findFirst({
        where: {
          conversationId: conversation.id,
          sender: SupportSender.ADMIN,
        },
      });

      if (adminAlreadyReplied) {
        return res.json({
          ok: true,
          success: true,
          type: "admin_only",
          conversationId: conversation.id,
          message:
            "Votre message a été transmis à un conseiller. Vous recevrez une réponse personnalisée dès que possible.",
        });
      }

      // 4️⃣ Réponse "bot" par défaut
      const botAnswer =
        "Je suis l’assistant Smart Business Corp. Pour effectuer un retrait, allez dans l’onglet « Retraits », choisissez le montant puis validez. " +
        "Les retraits sont traités dans les fenêtres prévues par la stratégie. " +
        "Si vous rencontrez un problème (paiement, blocage, erreur), décrivez-le clairement et un administrateur prendra le relais.";

      const botMessage = await prisma.supportMessage.create({
        data: {
          conversationId: conversation.id,
          sender: SupportSender.BOT,
          text: botAnswer,
          seenByAdmin: false,
          seenByUser: false,
        },
      });

      await prisma.supportConversation.update({
        where: { id: conversation.id },
        data: { status: SupportStatus.OPEN },
      });

      return res.json({
        ok: true,
        success: true,
        type: "bot",
        conversationId: conversation.id,
        message: botMessage.text,
      });
    } catch (err) {
      logger.error({ err }, "Erreur /api/support/chat");
      return res.status(500).json({
        ok: false,
        success: false,
        message:
          "Erreur serveur lors du traitement de votre demande d'assistance.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                  SUPPORT – LISTE CONVERSATIONS (CLIENT)            */
/* ------------------------------------------------------------------ */

app.get(
  "/api/support/conversations",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const conversations = await prisma.supportConversation.findMany({
        where: { userId },
        orderBy: { updatedAt: "desc" },
        include: {
          messages: {
            orderBy: { createdAt: "desc" },
            take: 1,
          },
        },
      });

      const shaped = conversations.map((c) => {
        const last = c.messages[0];
        return {
          id: c.id,
          status: c.status,
          lastMessage: last
            ? {
                id: last.id,
                sender: last.sender,
                text: last.text,
                createdAt: last.createdAt,
              }
            : null,
          updatedAt: c.updatedAt,
        };
      });

      return res.json({
        success: true,
        conversations: shaped,
      });
    } catch (err) {
      logger.error({ err }, "Erreur GET /api/support/conversations (client)");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération de vos conversations d'assistance.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                 SUPPORT – MESSAGES D’UNE CONVERSATION               */
/*                          (CLIENT / LECTURE)                         */
/* ------------------------------------------------------------------ */

app.get(
  "/api/support/conversations/:id/messages",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const conversationId = Number(req.params.id);

      if (Number.isNaN(conversationId)) {
        return res.status(400).json({
          success: false,
          message: "ID de conversation invalide.",
        });
      }

      const conversation = await prisma.supportConversation.findFirst({
        where: { id: conversationId, userId },
      });

      if (!conversation) {
        return res.status(404).json({
          success: false,
          message: "Conversation introuvable.",
        });
      }

      const messages = await prisma.supportMessage.findMany({
        where: { conversationId },
        orderBy: { createdAt: "asc" },
      });

      // On marque comme "vus par l'utilisateur" les messages ADMIN / BOT non lus
      await prisma.supportMessage.updateMany({
        where: {
          conversationId,
          sender: { in: ["ADMIN", "BOT"] },
          seenByUser: false,
        },
        data: { seenByUser: true },
      });

      return res.json({
        success: true,
        conversation: {
          id: conversation.id,
          status: conversation.status,
        },
        messages,
      });
    } catch (err) {
      logger.error(
        { err },
        "Erreur GET /api/support/conversations/:id/messages (client)"
      );
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération des messages d'assistance.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                           ENDPOINT TEST                             */
/* ------------------------------------------------------------------ */

app.get("/", (_req, res) => res.json({ message: "API running" }));

/* ------------------------------------------------------------------ */
/*                              REGISTER                               */
/* ------------------------------------------------------------------ */

app.post(
  "/api/register",
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
      } = parseResult.data;

      if (!isStrongPassword(password)) {
        return res.status(400).json({
          success: false,
          message:
            "Mot de passe trop faible. Minimum 8 caractères avec au moins une lettre et un chiffre.",
        });
      }

      const cleanedEmail =
        email && email.trim() !== "" ? email.trim().toLowerCase() : null;

      const existingPhone = await prisma.user.findUnique({ where: { phone } });
      if (existingPhone) {
        return res.status(400).json({
          success: false,
          message: "Ce numéro est déjà utilisé.",
        });
      }

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

      const passwordHash = await bcrypt.hash(password, 10);

      // 🔐 Hash de la réponse de sécurité
      const securityAnswerHash = await bcrypt.hash(securityAnswer.trim(), 10);

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
        },
      });

      res.json({ success: true, userId: user.id });
    } catch (err) {
      logger.error({ err }, "Erreur register");
      res.status(500).json({ success: false });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                                LOGIN                                */
/* ------------------------------------------------------------------ */

app.post("/api/login", loginLimiter, async (req: Request, res: Response) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);

    if (!parseResult.success) {
      const msg =
        parseResult.error.issues[0]?.message ||
        "Données de connexion invalides.";
      return res.status(400).json({ success: false, message: msg });
    }

    const { phone, password } = parseResult.data;

    const nowTs = Date.now();
    const clientIp = getClientIp(req);
    const attemptInfo = loginAttempts.get(phone);

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
      const current = attemptInfo || {
        count: 0,
        lockedUntil: null,
      };

      current.count += 1;

      if (current.count >= MAX_LOGIN_ATTEMPTS) {
        current.lockedUntil = nowTs + LOCK_TIME_MS;
        current.count = 0;
        loginAttempts.set(phone, current);

        logger.warn(
          { phone, ip: clientIp },
          "Compte bloqué 5 minutes après trop de tentatives échouées (user inexistant)."
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
      const current = attemptInfo || {
        count: 0,
        lockedUntil: null,
      };

      current.count += 1;

      if (current.count >= MAX_LOGIN_ATTEMPTS) {
        current.lockedUntil = nowTs + LOCK_TIME_MS;
        current.count = 0;
        loginAttempts.set(phone, current);

        logger.warn(
          { phone, userId: user.id, ip: clientIp },
          "Compte bloqué 5 minutes après trop de tentatives échouées (mauvais mot de passe)."
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

    if (loginAttempts.has(phone)) {
      loginAttempts.delete(phone);
    }

    const jti = randomUUID();
    const ip = clientIp;
    const ipHash = hashIp(ip);

    await prisma.session.create({
      data: {
        jti,
        userId: user.id,
        userAgent: req.headers["user-agent"] || null,
        ipHash,
        lastSeenAt: new Date(),
      },
    });

    const token = jwt.sign(
      { userId: user.id, role: user.role, jti },
      JWT_SECRET!,
      { expiresIn: "7d" }
    );

    res.cookie(COOKIE_NAME, token, AUTH_COOKIE_OPTIONS);

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.fullName,
        phone: user.phone,
        role: user.role,
      },
    });
  } catch (err) {
    logger.error({ err }, "Erreur login");
    res.status(500).json({ success: false });
  }
});

/* ------------------------------------------------------------------ */
/*                               LOGOUT                                */
/* ------------------------------------------------------------------ */

app.post(
  "/api/logout",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const jti = (req as any).sessionJti as string | undefined;

      if (jti) {
        await prisma.session.updateMany({
          where: { jti, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }

      res
        .clearCookie(COOKIE_NAME, BASE_COOKIE_OPTIONS)
        .json({
          success: true,
          message: "Déconnexion réussie.",
        });
    } catch (err) {
      logger.error({ err }, "Erreur logout");
      res
        .status(500)
        .json({ success: false, message: "Erreur lors du logout." });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                             LOGOUT ALL                              */
/* ------------------------------------------------------------------ */

app.post(
  "/api/logout-all",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      await prisma.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      res
        .clearCookie(COOKIE_NAME, BASE_COOKIE_OPTIONS)
        .json({
          success: true,
          message: "Toutes vos sessions ont été déconnectées.",
        });
    } catch (err) {
      logger.error({ err }, "Erreur logout-all");
      res.status(500).json({
        success: false,
        message: "Erreur lors du logout-all.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    MOT DE PASSE OUBLIÉ – ÉTAPE 1                    */
/*            Vérification du numéro & retour question secrète         */
/* ------------------------------------------------------------------ */

app.post(
  "/api/password/forgot/start",
  async (req: Request, res: Response) => {
    try {
      const parsed = forgotPasswordStartSchema.safeParse(req.body);
      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { phone } = parsed.data;

      const user = await prisma.user.findUnique({
        where: { phone },
      });

      if (!user) {
        // ⚠ Tu m'as demandé de dire explicitement si le numéro n'existe pas
        return res.status(404).json({
          success: false,
          message:
            "Aucun compte trouvé avec ce numéro de téléphone.",
        });
      }

      if (!user.securityQuestion || !user.securityAnswerHash) {
        return res.status(400).json({
          success: false,
          message:
            "Ce compte n'a pas encore de question de sécurité configurée. Merci de contacter l'assistance.",
        });
      }

      return res.json({
        success: true,
        phone,
        securityQuestion: user.securityQuestion,
      });
    } catch (err) {
      logger.error({ err }, "Erreur /api/password/forgot/start");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors du démarrage de la réinitialisation.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    MOT DE PASSE OUBLIÉ – ÉTAPE 2                    */
/*   Vérification de la réponse à la question & génération resetToken  */
/* ------------------------------------------------------------------ */

app.post(
  "/api/password/forgot/verify",
  async (req: Request, res: Response) => {
    try {
      const parsed = forgotPasswordVerifySchema.safeParse(req.body);
      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { phone, answer } = parsed.data;

      const nowTs = Date.now();
      const attemptInfo = securityAnswerAttempts.get(phone);

      if (attemptInfo?.lockedUntil && nowTs < attemptInfo.lockedUntil) {
        const remainingMs = attemptInfo.lockedUntil - nowTs;
        const remainingMin = Math.ceil(remainingMs / 60000);

        return res.status(429).json({
          success: false,
          message: `Trop de tentatives de réponse. Réessayez dans environ ${remainingMin} minute(s).`,
        });
      }

      const user = await prisma.user.findUnique({
        where: { phone },
      });

      if (
        !user ||
        !user.securityAnswerHash ||
        !user.securityQuestion
      ) {
        // on incrémente aussi en cas d'utilisateur inexistant
        const current = attemptInfo || {
          count: 0,
          lockedUntil: null,
        };
        current.count += 1;

        if (current.count >= MAX_SECURITY_ANSWER_ATTEMPTS) {
          current.lockedUntil =
            nowTs + SECURITY_ANSWER_LOCK_TIME_MS;
          current.count = 0;
        }

        securityAnswerAttempts.set(phone, current);

        return res.status(401).json({
          success: false,
          message: "Réponse incorrecte.",
        });
      }

      const ok = await bcrypt.compare(
        answer.trim(),
        user.securityAnswerHash
      );

      if (!ok) {
        const current = attemptInfo || {
          count: 0,
          lockedUntil: null,
        };
        current.count += 1;

        if (current.count >= MAX_SECURITY_ANSWER_ATTEMPTS) {
          current.lockedUntil =
            nowTs + SECURITY_ANSWER_LOCK_TIME_MS;
          current.count = 0;

          logger.warn(
            { phone, userId: user.id },
            "Compte verrouillé temporairement après trop de mauvaises réponses à la question secrète."
          );
        }

        securityAnswerAttempts.set(phone, current);

        return res.status(401).json({
          success: false,
          message: "Réponse incorrecte.",
        });
      }

      // ✅ Réponse correcte → on reset les tentatives
      if (securityAnswerAttempts.has(phone)) {
        securityAnswerAttempts.delete(phone);
      }

      // 🎫 On génère un resetToken (JWT court) utilisable pour changer le mot de passe
      const resetToken = jwt.sign(
        {
          userId: user.id,
          phone: user.phone,
          purpose: "password_reset",
        },
        JWT_SECRET!,
        { expiresIn: "10m" }
      );

      return res.json({
        success: true,
        resetToken,
        message:
          "Réponse correcte. Vous pouvez maintenant choisir un nouveau mot de passe.",
      });
    } catch (err) {
      logger.error({ err }, "Erreur /api/password/forgot/verify");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la vérification de la réponse.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    MOT DE PASSE OUBLIÉ – ÉTAPE 3                    */
/*       Réinitialisation effective du mot de passe avec resetToken    */
/* ------------------------------------------------------------------ */

app.post(
  "/api/password/forgot/reset",
  async (req: Request, res: Response) => {
    try {
      const parsed = forgotPasswordResetSchema.safeParse(req.body);
      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { resetToken, newPassword } = parsed.data;

      if (!isStrongPassword(newPassword)) {
        return res.status(400).json({
          success: false,
          message:
            "Le nouveau mot de passe doit contenir au moins 8 caractères, avec au moins une lettre et un chiffre.",
        });
      }

      let payload: {
        userId: number;
        phone: string;
        purpose?: string;
      };

      try {
        payload = jwt.verify(resetToken, JWT_SECRET!) as any;
      } catch (err) {
        return res.status(401).json({
          success: false,
          message: "Token de réinitialisation invalide ou expiré.",
        });
      }

      if (payload.purpose !== "password_reset") {
        return res.status(401).json({
          success: false,
          message: "Token de réinitialisation invalide.",
        });
      }

      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
      });

      if (!user || user.phone !== payload.phone) {
        return res.status(400).json({
          success: false,
          message: "Utilisateur introuvable pour ce token.",
        });
      }

      const newHash = await bcrypt.hash(newPassword.trim(), 10);

      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordHash: newHash,
        },
      });

      // 🔐 On révoque toutes les sessions actives de l'utilisateur
      await prisma.session.updateMany({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      return res.json({
        success: true,
        message:
          "Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous reconnecter.",
      });
    } catch (err) {
      logger.error({ err }, "Erreur /api/password/forgot/reset");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la réinitialisation du mot de passe.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                          DEMANDE DE RETRAIT                         */
/* ------------------------------------------------------------------ */

app.post(
  "/api/withdrawals",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      // ✅ Normalisation / validation du body
      const parseResult = withdrawalSchema.safeParse({
        ...req.body,
        amount:
          typeof req.body.amount === "string"
            ? Number(req.body.amount)
            : req.body.amount,
      });

      if (!parseResult.success) {
        const msg =
          parseResult.error.issues[0]?.message ||
          "Données de retrait invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { amount, waveNumber, note } = parseResult.data;
      const userId = req.user!.id;

      // 🔐 Fenêtre hebdo (lundi 00:00 → maintenant)
      const now = new Date();
      const monday = new Date(now);
      monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
      monday.setHours(0, 0, 0, 0);

      const weeklyWithdrawalLimit = 2;

      // 🧱 TOUT ce qui est critique passe dans une transaction
      const { withdrawal, withdrawalsThisWeek } = await prisma.$transaction(
        async (tx) => {
          // 1️⃣ Compter les retraits de la semaine (dans la transaction)
          const withdrawalsThisWeek = await tx.withdrawal.count({
            where: {
              userId,
              createdAt: { gte: monday },
            },
          });

          if (withdrawalsThisWeek >= weeklyWithdrawalLimit) {
            const error: any = new Error("WEEKLY_LIMIT_REACHED");
            error.meta = { withdrawalsThisWeek };
            throw error;
          }

          // ✅ NOTIFICATIONS (dernières 5) pour affichage dans "Activité récente"
      const notifications = await prisma.notification.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" },
            take: 5,
          });


          // 2️⃣ Récupérer le wallet
          const wallet = await tx.wallet.findUnique({
            where: { userId },
          });

          if (!wallet) {
            const error: any = new Error("WALLET_NOT_FOUND");
            throw error;
          }

          // 3️⃣ Calculer le solde disponible = balance - somme des retraits PENDING
          const agg = await tx.withdrawal.aggregate({
            _sum: { amount: true },
            where: {
              userId,
              status: "PENDING",
            },
          });

          const pendingSum = agg._sum.amount ?? 0;
          const availableBalance = wallet.balance - pendingSum;

          if (amount > availableBalance) {
            const error: any = new Error("INSUFFICIENT_AVAILABLE_BALANCE");
            error.meta = {
              walletBalance: wallet.balance,
              pendingWithdrawals: pendingSum,
              availableBalance,
            };
            throw error;
          }

          // 4️⃣ Création de la demande de retrait (toujours PENDING)
          const withdrawal = await tx.withdrawal.create({
            data: {
              userId,
              amount,
              waveNumber,
              note,
              status: "PENDING",
            },
          });

          return { withdrawal, withdrawalsThisWeek };
        }
      );

      // 📨 MAIL ADMIN POUR CHAQUE DEMANDE DE RETRAIT (hors transaction)
      try {
        const user = await prisma.user.findUnique({ where: { id: userId } });

        if (user && isEmailEnabled) {
  await transporter.sendMail({
    from: EMAIL_FROM,
    to: "contact@smartbusinesscorp.org",
    subject: "Nouvelle demande de retrait (PENDING)",
    html: `
      <h3>Nouvelle demande de retrait</h3>
      <p><strong>Client :</strong> ${user.fullName} (#${user.id})</p>
      <p><strong>Téléphone :</strong> ${user.phone}</p>
      <p><strong>Email :</strong> ${user.email || "-"}</p>
      <p><strong>Montant demandé :</strong> ${amount.toLocaleString(
        "fr-FR"
      )} XOF</p>
      <p><strong>Numéro Wave :</strong> ${waveNumber}</p>
      <p><strong>ID Retrait :</strong> ${withdrawal.id}</p>
      <p>Statut actuel : <strong>PENDING</strong></p>
    `,
  });
}

      } catch (mailErr) {
        console.error("Erreur envoi mail admin retrait:", mailErr);
        // on ne bloque pas la réponse client si le mail échoue
      }

      // ✅ Réponse identique à avant, avec remainingWithdrawals recalculé
      return res.json({
        success: true,
        withdrawal,
        remainingWithdrawals: weeklyWithdrawalLimit - withdrawalsThisWeek - 1,
        weeklyWithdrawalLimit,
      });
    } catch (err: any) {
      // 🔍 Gestion des erreurs métier explicites
      if (err?.message === "WEEKLY_LIMIT_REACHED") {
        return res.status(400).json({
          success: false,
          message: "Limite de retraits hebdomadaire atteinte.",
        });
      }

      if (err?.message === "WALLET_NOT_FOUND") {
        logger.error({ err, userId: (req as any).user?.id }, "Wallet introuvable");
        return res.status(400).json({
          success: false,
          message:
            "Aucun portefeuille associé à ce compte. Contactez le support.",
        });
      }

      if (err?.message === "INSUFFICIENT_AVAILABLE_BALANCE") {
        const meta = err.meta || {};
        return res.status(400).json({
          success: false,
          code: "INSUFFICIENT_BALANCE",
          message: "Solde insuffisant pour effectuer ce retrait.",
          // 🔎 On expose le solde disponible plutôt que le solde brut
          walletBalance: meta.availableBalance ?? 0,
          pendingWithdrawals: meta.pendingWithdrawals ?? 0,
        });
      }

      logger.error({ err }, "Erreur retrait");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de la demande de retrait.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                         LISTE DES RETRAITS                          */
/* ------------------------------------------------------------------ */

app.get(
  "/api/withdrawals",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const withdrawals = await prisma.withdrawal.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      });

      res.json({
        success: true,
        withdrawals,
      });
    } catch (err) {
      console.error("Erreur liste retraits:", err);
      res.status(500).json({ success: false });
    }
  }
);

// 🔔 Notifications pour une nouvelle demande d'investissement
async function notifyNewInvestmentSafely(params: {
  userId: number;
  amountXOF: number;
  investmentId: number;
}) {
  const { userId, amountXOF, investmentId } = params;

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      logger.warn(
        { userId },
        "Impossible d'envoyer les notifications: utilisateur introuvable."
      );
      return;
    }

    const montantTxt = amountXOF.toLocaleString("fr-FR");

    // 📧 Mail admin (avec timeout interne pour éviter de bloquer trop longtemps)
    // 📧 Mail admin (Brevo SMTP)
if (isEmailEnabled) {
  try {
    await Promise.race([
      transporter.sendMail({
        from: EMAIL_FROM,
        to: "contact@smartbusinesscorp.org",
        subject: "Nouvelle demande d'investissement (PENDING)",
        html: `
          <h3>Nouvelle demande d'investissement</h3>
          <p><strong>Client :</strong> ${user.fullName} (#${user.id})</p>
          <p><strong>Téléphone :</strong> ${user.phone}</p>
          <p><strong>Email :</strong> ${user.email || "-"}</p>
          <p><strong>Montant :</strong> ${montantTxt} XOF</p>
          <p><strong>ID Investissement :</strong> ${investmentId}</p>
          <p>Statut actuel : <strong>PENDING</strong></p>
        `,
      }),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("Timeout email nouvelle demande investissement")),
          10_000
        )
      ),
    ]);
  } catch (err) {
    logger.error(
      { err },
      "Erreur notification email nouvelle demande investissement"
    );
  }
} else {
  logger.warn(
    "Config SMTP Brevo incomplète: pas d'email nouvelle demande investissement."
  );
}

    // 📲 SMS admin
    try {
      await notifyAdminSms(
        `Nouvelle demande d'investissement: ${montantTxt} XOF (ID #${investmentId})`
      );
    } catch (e) {
      logger.error({ e }, "Erreur notif SMS nouvelle demande investissement");
    }

    // 💬 WhatsApp admin
    try {
      await notifyAdminWhatsApp(
        `Nouvelle demande d'investissement: ${montantTxt} XOF (ID #${investmentId})`
      );
    } catch (e) {
      logger.error({ e }, "Erreur notif WhatsApp nouvelle demande investissement");
    }

    // Notifications client (si numéro dispo)
    if (user.phone) {
      try {
        await sendSms(
          user.phone,
          `Smart Business Corp: votre demande d'investissement de ${montantTxt} XOF est en attente de validation par un administrateur.`
        );
      } catch (e) {
        logger.error({ e }, "Erreur SMS client nouvelle demande investissement");
      }

      try {
        await sendWhatsAppText(
          user.phone,
          `Smart Business Corp\n\nVotre demande d'investissement de ${montantTxt} XOF a été enregistrée.\n\nStatut: EN ATTENTE DE VALIDATION.\nVous recevrez une confirmation dès que l'administrateur aura vérifié le paiement.`
        );
      } catch (e) {
        logger.error(
          { e },
          "Erreur WhatsApp client nouvelle demande investissement"
        );
      }
    }
  } catch (err) {
    logger.error(
      { err },
      "Erreur globale notification nouvelle demande investissement (mail/SMS/WhatsApp)"
    );
  }
}

/* ------------------------------------------------------------------ */
/*             CRÉER UN INVESTISSEMENT (PENDING + NOTIFS)             */
/* ------------------------------------------------------------------ */

app.post(
  "/api/investments",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const parsed = investmentSchema.safeParse({
        ...req.body,
        amountXOF:
          typeof req.body.amountXOF === "string"
            ? Number(req.body.amountXOF)
            : req.body.amountXOF,
      });

      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données d'investissement invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { amountXOF } = parsed.data;
      const allowedTiers = [10000, 25000, 50000, 100000, 250000, 500000];

      if (!allowedTiers.includes(amountXOF)) {
        return res.status(400).json({
          success: false,
          message: "Palier non autorisé.",
        });
      }

      const userId = req.user!.id;

      let tier = await prisma.tier.findFirst({ where: { amountXOF } });
      if (!tier) {
        tier = await prisma.tier.create({ data: { amountXOF } });
      }

      const now = new Date();
      const endDate = new Date(now);
      endDate.setDate(now.getDate() + 90);

      const investment = await prisma.investment.create({
        data: {
          principalXOF: amountXOF,
          accruedGainXOF: 0,
          status: "PENDING",
          createdAt: now,
          endDate,
          userId,
          tierId: tier.id,
        },
      });

      // ✅ On répond TOUT DE SUITE au frontend
      res.status(201).json({ success: true, investment });

      // 🔔 Notifications en arrière-plan (ne bloquent pas la réponse)
      void notifyNewInvestmentSafely({
        userId,
        amountXOF,
        investmentId: investment.id,
      });
    } catch (err) {
      console.error("Erreur investments (POST):", err);
      return res.status(500).json({ success: false });
    }
  }
);


/* ------------------------------------------------------------------ */
/*                 ADMIN – ROUTER INVESTISSEMENTS EXISTANT            */
/* ------------------------------------------------------------------ */

app.use(
  "/api/admin/investments",
  authMiddleware,
  adminMiddleware,
  adminInvestmentsRouter
);

/* ------------------------------------------------------------------ */
/*                    LISTE INVESTISSEMENTS (CLIENT)                   */
/* ------------------------------------------------------------------ */

app.get(
  "/api/investments",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const investments = await prisma.investment.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      });

      res.json({
        success: true,
        investments,
      });
    } catch (err) {
      console.error("Erreur investments (GET):", err);
      res.status(500).json({ success: false });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                 DÉTAIL D’UN INVESTISSEMENT (CLIENT)                */
/* ------------------------------------------------------------------ */

app.get(
  "/api/investments/:id",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const id = Number(req.params.id);

      if (Number.isNaN(id)) {
        return res.status(400).json({
          success: false,
          message: "ID d'investissement invalide.",
        });
      }

      const investment = await prisma.investment.findFirst({
        where: { id, userId },
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
      console.error("Erreur investments (GET /:id):", err);
      return res.status(500).json({ success: false });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    HISTORIQUE TRANSACTIONS (CLIENT)                 */
/* ------------------------------------------------------------------ */

app.get(
  "/api/transactions",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const [investments, withdrawals] = await Promise.all([
        prisma.investment.findMany({
          where: { userId },
          orderBy: { createdAt: "desc" },
        }),
        prisma.withdrawal.findMany({
          where: { userId },
          orderBy: { createdAt: "desc" },
        }),
      ]);

      const events: {
        id: string;
        type: "INVESTMENT" | "WITHDRAWAL";
        step: "REQUEST" | "FINAL";
        createdAt: string;
        amount: number;
        status: string;
      }[] = [];

      // Une seule ligne par investissement (ligne "finale")
      for (const inv of investments) {
        events.push({
          id: `INV-${inv.id}`,
          type: "INVESTMENT",
          step: "FINAL",
          createdAt: inv.createdAt.toISOString(),
          amount: inv.principalXOF,
          status: inv.status, // PENDING | ACTIVE | REJECTED | CLOSED
        });
      }

      // Deux lignes pour les retraits : demande + statut final (si traité)
      for (const w of withdrawals) {
        // 1) demande de retrait
        events.push({
          id: `WDR-REQ-${w.id}`,
          type: "WITHDRAWAL",
          step: "REQUEST",
          createdAt: w.createdAt.toISOString(),
          amount: w.amount,
          status: "PENDING",
        });

        // 2) résultat final (si pas PENDING)
        if (w.status !== "PENDING") {
          events.push({
            id: `WDR-FINAL-${w.id}`,
            type: "WITHDRAWAL",
            step: "FINAL",
            createdAt: (w.processedAt ?? w.createdAt).toISOString(),
            amount: w.amount,
            status: w.status, // PROCESSED ou REJECTED
          });
        }
      }

      // tri du plus récent au plus ancien
      events.sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );

      return res.json({
        success: true,
        transactions: events,
      });
    } catch (err) {
      logger.error({ err }, "Erreur GET /api/transactions");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération de l'historique des transactions.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                              DASHBOARD                              */
/* ------------------------------------------------------------------ */

app.get(
  "/api/dashboard",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user)
        return res.status(404).json({
          success: false,
          message: "Utilisateur introuvable.",
        });

      const investments = await prisma.investment.findMany({
        where: { userId, status: "ACTIVE" },
        orderBy: { createdAt: "desc" },
      });

      const withdrawals = await prisma.withdrawal.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      });

      const wallet = await prisma.wallet.findUnique({
        where: { userId },
      });

      const capitalInvested = investments.reduce(
        (s, i) => s + i.principalXOF,
        0
      );

      const totalGains = investments.reduce((s, i) => s + i.accruedGainXOF, 0);

      const withdrawalsProcessed = withdrawals
        .filter((w) => w.status === "PROCESSED")
        .reduce((s, w) => s + w.amount, 0);

      const computedWalletBalance = totalGains - withdrawalsProcessed;

      const walletBalance =
        wallet?.balance !== undefined ? wallet.balance : computedWalletBalance;

      const now = new Date();
      const monday = new Date(now);
      monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
      monday.setHours(0, 0, 0, 0);

      const weeklyWithdrawalLimit = 2;

      const withdrawalsThisWeek = await prisma.withdrawal.count({
        where: { userId, createdAt: { gte: monday } },
      });

      // ✅ 1) JOURS RESTANTS (sur l'investissement actif le plus proche de l'échéance)
      const ONE_DAY_MS = 24 * 60 * 60 * 1000;
      const MAX_DAYS = 90;

      let minDaysRemaining: number | null = null;
      let minDaysElapsed: number | null = null;

      for (const inv of investments) {
        const elapsed = Math.min(
          MAX_DAYS,
          Math.max(
            0,
            Math.floor((Date.now() - inv.createdAt.getTime()) / ONE_DAY_MS)
          )
        );
        const remaining = Math.max(0, MAX_DAYS - elapsed);

        if (minDaysRemaining === null || remaining < minDaysRemaining) {
          minDaysRemaining = remaining;
          minDaysElapsed = elapsed;
        }
      }

      // ✅ 2) NOTIFICATIONS (dernières 5) pour les inclure dans "Activité récente"
      const notifications = await prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        take: 5,
      });

      const recentEvents = [
  // Withdrawals
  ...withdrawals.slice(0, 5).map((w) => ({
    type: "WITHDRAWAL" as const,
    date: w.createdAt.toISOString(),
    label: w.status === "PENDING" ? "Retrait demandé" : "Retrait traité",
    detail: `${w.amount.toLocaleString("fr-FR")} XOF`,
  })),

  // Investments
  ...investments.slice(0, 5).map((i) => ({
    type: "INVESTMENT" as const,
    date: i.createdAt.toISOString(),
    label: "Investissement lancé",
    detail: `${i.principalXOF.toLocaleString("fr-FR")} XOF`,
  })),

  // Notifications (dont la notif J+90 "échéance")
  ...notifications.map((n) => ({
    type: "INVESTMENT" as const, // on réutilise le type existant côté front
    date: n.createdAt.toISOString(),
    label: n.title || "Notification",
    detail: n.message || "",
  })),
]
  .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
  .slice(0, 5);

      res.json({
        success: true,
        data: {
          user,
          capitalInvested,
          totalGains,
          walletBalance,
          activeInvestmentsCount: investments.length,
          withdrawalsPending: withdrawals
            .filter((w) => w.status === "PENDING")
            .reduce((s, w) => s + w.amount, 0),
          recentEvents,

          // ✅ NOUVEAU : jours restants pour le dashboard
          minDaysRemaining,
          minDaysElapsed,

          remainingWithdrawals: Math.max(
            weeklyWithdrawalLimit - withdrawalsThisWeek,
            0
          ),
          weeklyWithdrawalLimit,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur dashboard");
      res.status(500).json({ success: false });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                             NOTIFICATIONS                           */
/* ------------------------------------------------------------------ */

// Nombre de notifications non lues
app.get(
  "/api/notifications/unread-count",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const count = await prisma.notification.count({
        where: {
          userId,
          readAt: null,
        },
      });

      return res.json({ success: true, unreadCount: count });
    } catch (err) {
      logger.error({ err }, "Erreur GET /api/notifications/unread-count");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors du comptage des notifications.",
      });
    }
  }
);

// Liste des notifications (du plus récent au plus ancien)
app.get(
  "/api/notifications",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const limitRaw = (req.query.limit as string) || "50";
      let limit = parseInt(limitRaw, 10);
      if (isNaN(limit) || limit <= 0) limit = 50;
      if (limit > 200) limit = 200;

      const notifications = await prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        take: limit,
      });

      return res.json({
        success: true,
        notifications,
      });
    } catch (err) {
      logger.error({ err }, "Erreur GET /api/notifications");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de la récupération des notifications.",
      });
    }
  }
);

// Marquer les notifications comme lues (toutes ou une liste d'IDs)
app.post(
  "/api/notifications/mark-read",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const { ids, all } = req.body as { ids?: number[]; all?: boolean };

      const where: any = {
        userId,
        readAt: null,
      };

      if (!all && ids && ids.length > 0) {
        where.id = { in: ids };
      }

      await prisma.notification.updateMany({
        where,
        data: {
          readAt: new Date(),
        },
      });

      return res.json({ success: true });
    } catch (err) {
      logger.error({ err }, "Erreur POST /api/notifications/mark-read");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de la mise à jour des notifications.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                                PROFIL                              */
/* ------------------------------------------------------------------ */

app.get(
  "/api/profile",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Utilisateur introuvable.",
        });
      }

      return res.json({
        success: true,
        profile: {
          fullName: user.fullName,
          phone: user.phone,
          email: user.email,
          waveNumber: user.waveNumber,
          orangeMoneyNumber: user.orangeMoneyNumber ?? null,
          country: user.country ?? null,
          city: user.city ?? null,
          birthDate: user.birthDate ? user.birthDate.toISOString() : null,
          idType: user.idType ?? null,
          idNumber: user.idNumber ?? null,
          securityQuestion: user.securityQuestion ?? null,
          // on NE renvoie PAS la réponse / hash
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur GET /api/profile");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors du chargement du profil.",
      });
    }
  }
);

app.patch(
  "/api/profile",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const parsed = profileUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données de profil invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const {
        email,
        waveNumber,
        orangeMoneyNumber,
        country,
        city,
        birthDate,
        idType,
        idNumber,
        securityQuestion,
        securityAnswer,
      } = parsed.data;

      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Utilisateur introuvable.",
        });
      }

      const data: any = {};

      // Email (null si vide)
      if (typeof email !== "undefined") {
        data.email = email && email.trim() !== "" ? email.trim().toLowerCase() : null;
      }

      if (typeof waveNumber !== "undefined") {
        data.waveNumber = waveNumber.trim();
      }

      if (typeof orangeMoneyNumber !== "undefined") {
        data.orangeMoneyNumber =
          orangeMoneyNumber && orangeMoneyNumber.trim() !== ""
            ? orangeMoneyNumber.trim()
            : null;
      }

      if (typeof country !== "undefined") {
        data.country =
          country && country.trim() !== "" ? country.trim() : null;
      }

      if (typeof city !== "undefined") {
        data.city = city && city.trim() !== "" ? city.trim() : null;
      }

      // BirthDate : on autorise la MISE EN PLACE si elle est encore null, ensuite lock
      if (typeof birthDate !== "undefined" && !user.birthDate && birthDate) {
        data.birthDate = new Date(birthDate);
      }

      if (typeof idType !== "undefined") {
        data.idType = idType && idType.trim() !== "" ? idType.trim() : null;
      }

      if (typeof idNumber !== "undefined") {
        data.idNumber =
          idNumber && idNumber.trim() !== "" ? idNumber.trim() : null;
      }

      if (typeof securityQuestion !== "undefined") {
        data.securityQuestion =
          securityQuestion && securityQuestion.trim() !== ""
            ? securityQuestion.trim()
            : null;
      }

      if (typeof securityAnswer !== "undefined" && securityAnswer.trim() !== "") {
        // on stocke un hash
        const answerHash = await bcrypt.hash(securityAnswer.trim(), 10);
        data.securityAnswerHash = answerHash;
      }

      const updated = await prisma.user.update({
        where: { id: userId },
        data,
      });

      return res.json({
        success: true,
        profile: {
          fullName: updated.fullName,
          phone: updated.phone,
          email: updated.email,
          waveNumber: updated.waveNumber,
          orangeMoneyNumber: updated.orangeMoneyNumber ?? null,
          country: updated.country ?? null,
          city: updated.city ?? null,
          birthDate: updated.birthDate
            ? updated.birthDate.toISOString()
            : null,
          idType: updated.idType ?? null,
          idNumber: updated.idNumber ?? null,
          securityQuestion: updated.securityQuestion ?? null,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur PATCH /api/profile");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de la mise à jour du profil.",
      });
    }
  }
);

app.post(
  "/api/profile/password",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const parsed = passwordChangeSchema.safeParse(req.body);
      if (!parsed.success) {
        const msg =
          parsed.error.issues[0]?.message ||
          "Données de changement de mot de passe invalides.";
        return res.status(400).json({
          success: false,
          message: msg,
        });
      }

      const { currentPassword, newPassword } = parsed.data;

      if (!isStrongPassword(newPassword)) {
        return res.status(400).json({
          success: false,
          message:
            "Le nouveau mot de passe doit contenir au moins 8 caractères, avec au moins une lettre et un chiffre.",
        });
      }

      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Utilisateur introuvable.",
        });
      }

      const match = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!match) {
        return res.status(400).json({
          success: false,
          message: "Mot de passe actuel incorrect.",
        });
      }

      const newHash = await bcrypt.hash(newPassword, 10);

      await prisma.user.update({
        where: { id: userId },
        data: {
          passwordHash: newHash,
        },
      });

      return res.json({
        success: true,
        message: "Votre mot de passe a été mis à jour avec succès.",
      });
    } catch (err) {
      logger.error({ err }, "Erreur POST /api/profile/password");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors du changement de mot de passe.",
      });
    }
  }
);


/* ------------------------------------------------------------------ */
/*                        HISTORIQUE DU WALLET                         */
/* ------------------------------------------------------------------ */

app.get(
  "/api/wallet/history",
  authMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;

      const rawLimit = (req.query.limit as string) || "50";
      let limit = parseInt(rawLimit, 10);
      if (isNaN(limit) || limit <= 0) limit = 50;
      if (limit > 200) limit = 200;

      const entries = await prisma.ledgerEntry.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        take: limit,
      });

      return res.json({
        success: true,
        entries,
      });
    } catch (err) {
      logger.error({ err }, "Erreur wallet history");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération de l'historique du wallet.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                        ADMIN — DASHBOARD GLOBAL                     */
/* ------------------------------------------------------------------ */

app.get(
  "/api/admin/dashboard",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const totalUsers = await prisma.user.count();

      const investmentsAgg = await prisma.investment.aggregate({
        _sum: {
          principalXOF: true,
          accruedGainXOF: true,
        },
      });

      const totalInvested = investmentsAgg._sum.principalXOF || 0;
      const totalAccruedGain = investmentsAgg._sum.accruedGainXOF || 0;

      const pendingInvestmentsCount = await prisma.investment.count({
        where: { status: "PENDING" },
      });

      const walletAgg = await prisma.wallet.aggregate({
        _sum: { balance: true },
      });
      const totalWalletBalance = walletAgg._sum.balance || 0;

      const withdrawalsAgg = await prisma.withdrawal.aggregate({
        _sum: {
          amount: true,
        },
      });

      const totalWithdrawalsAmount = withdrawalsAgg._sum.amount || 0;

      const processedAgg = await prisma.withdrawal.aggregate({
        _sum: { amount: true },
        where: { status: "PROCESSED" },
      });
      const totalWithdrawalsProcessed = processedAgg._sum.amount || 0;

      const pendingAgg = await prisma.withdrawal.aggregate({
        _sum: { amount: true },
        where: { status: "PENDING" },
      });
      const totalWithdrawalsPending = pendingAgg._sum.amount || 0;

      const recentLedger = await prisma.ledgerEntry.findMany({
        orderBy: { createdAt: "desc" },
        take: 20,
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
            },
          },
        },
      });

      return res.json({
        success: true,
        data: {
          totalUsers,
          totalInvested,
          totalAccruedGain,
          totalWalletBalance,
          totalWithdrawalsAmount,
          totalWithdrawalsProcessed,
          totalWithdrawalsPending,
          recentLedger,
          pendingInvestmentsCount,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin dashboard");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération du dashboard admin.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                       ADMIN — LISTE DES UTILISATEURS                */
/* ------------------------------------------------------------------ */

app.get(
  "/api/admin/users",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const users = await prisma.user.findMany({
        orderBy: { createdAt: "desc" },
        include: {
          wallet: true,
          investments: true,
          withdrawals: true,
          sessions: {
            select: {
              createdAt: true,
              lastSeenAt: true,
            },
            orderBy: {
              lastSeenAt: "desc",
            },
            take: 1,
          },
        },
      });

      const result = users.map((u) => {
        const totalInvested = u.investments.reduce(
          (sum, inv) => sum + inv.principalXOF,
          0
        );

        const totalGains = u.investments.reduce(
          (sum, inv) => sum + inv.accruedGainXOF,
          0
        );

        const totalWithdrawalsProcessed = u.withdrawals
          .filter((w) => w.status === "PROCESSED")
          .reduce((sum, w) => sum + w.amount, 0);

        const walletBalance = u.wallet?.balance ?? 0;

        const lastSession = u.sessions[0];
        const lastSeenAt =
          lastSession?.lastSeenAt ?? lastSession?.createdAt ?? null;

        return {
          id: u.id,
          fullName: u.fullName,
          phone: u.phone,
          email: u.email,
          role: u.role,
          createdAt: u.createdAt,
          isActive: u.isActive,
          totalInvested,
          totalGains,
          totalWithdrawalsProcessed,
          walletBalance,
          lastSeenAt,
        };
      });

      return res.json({
        success: true,
        users: result,
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin users");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération de la liste des utilisateurs.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                         ADMIN — LEDGER GLOBAL                       */
/* ------------------------------------------------------------------ */

app.get(
  "/api/admin/ledger",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const { userId, type, source, limit, offset } = req.query;

      const take = Math.min(Number(limit) || 100, 500);
      const skip = Number(offset) || 0;

      const where: any = {};

      if (userId) {
        const idNum = Number(userId);
        if (!Number.isNaN(idNum)) {
          where.userId = idNum;
        }
      }

      if (type && typeof type === "string") {
        const upper = type.toUpperCase();
        if (upper === "CREDIT" || upper === "DEBIT") {
          where.type = upper;
        }
      }

      if (source && typeof source === "string") {
        where.source = source;
      }

      const [entries, totalCount] = await Promise.all([
        prisma.ledgerEntry.findMany({
          where,
          orderBy: { createdAt: "desc" },
          include: {
            user: {
              select: {
                id: true,
                fullName: true,
                phone: true,
              },
            },
          },
          skip,
          take,
        }),
        prisma.ledgerEntry.count({ where }),
      ]);

      return res.json({
        success: true,
        data: {
          totalCount,
          limit: take,
          offset: skip,
          entries,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin ledger");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération de l'historique comptable.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    ADMIN — INTÉGRITÉ WALLET VS LEDGER               */
/* ------------------------------------------------------------------ */

app.get(
  "/api/admin/wallet-integrity",
  authMiddleware,
  adminMiddleware,
  async (_req: AuthRequest, res: Response) => {
    try {
      const users = await prisma.user.findMany({
        include: {
          wallet: true,
          ledgerEntries: true,
        },
      });

      const rows = users.map((u) => {
        const computedBalance = u.ledgerEntries.reduce((sum, entry) => {
          if (entry.type === "CREDIT") return sum + entry.amount;
          if (entry.type === "DEBIT") return sum - entry.amount;
          return sum;
        }, 0);

        const walletBalance = u.wallet?.balance ?? 0;
        const diff = walletBalance - computedBalance;

        return {
          userId: u.id,
          fullName: u.fullName,
          phone: u.phone,
          walletBalance,
          computedBalance,
          diff,
        };
      });

      const mismatches = rows.filter((r) => r.diff !== 0);

      return res.json({
        success: true,
        data: {
          totalUsers: rows.length,
          mismatchesCount: mismatches.length,
          mismatches,
          rows,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur wallet-integrity");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la vérification de l'intégrité des wallets.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                    ADMIN — WALLET SYNC DEPUIS LEDGER                */
/* ------------------------------------------------------------------ */

app.post(
  "/api/admin/wallet-sync/:userId",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const adminId = req.user!.id;
      const userId = Number(req.params.userId);

      if (Number.isNaN(userId)) {
        return res.status(400).json({
          success: false,
          message: "userId invalide.",
        });
      }

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { wallet: true },
      });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Utilisateur introuvable.",
        });
      }

      const oldBalance = user.wallet?.balance ?? 0;

      const creditAgg = await prisma.ledgerEntry.aggregate({
        where: { userId, type: "CREDIT" },
        _sum: { amount: true },
      });

      const debitAgg = await prisma.ledgerEntry.aggregate({
        where: { userId, type: "DEBIT" },
        _sum: { amount: true },
      });

      const totalCredits = creditAgg._sum.amount ?? 0;
      const totalDebits = debitAgg._sum.amount ?? 0;

      const computedBalance = totalCredits - totalDebits;

      const wallet = await prisma.wallet.upsert({
        where: { userId },
        update: {
          balance: computedBalance,
        },
        create: {
          userId,
          balance: computedBalance,
        },
      });

      logger.info(
        {
          adminId,
          userId,
          oldBalance,
          newBalance: wallet.balance,
          computedBalance,
          totalCredits,
          totalDebits,
        },
        "[ADMIN] Wallet resynchronisé à partir du Ledger"
      );

      return res.json({
        success: true,
        data: {
          userId,
          fullName: user.fullName,
          phone: user.phone,
          oldBalance,
          newBalance: wallet.balance,
          computedBalance,
          totalCredits,
          totalDebits,
        },
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin wallet-sync");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la resynchronisation du wallet.",
      });
    }
  }
);

/* ------------------------------------------------------------------ */
/*                     ADMIN — SUPPORT CONVERSATIONS                   */
/* ------------------------------------------------------------------ */

// Liste des conversations classées du + récent au + ancien
app.get(
  "/api/admin/support/conversations",
  authMiddleware,
  adminMiddleware,
  async (_req: AuthRequest, res: Response) => {
    try {
      const conversations = await prisma.supportConversation.findMany({
        orderBy: { updatedAt: "desc" },
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
              email: true,
            },
          },
          messages: {
            orderBy: { createdAt: "desc" },
            take: 1,
          },
        },
      });

      const shaped = conversations.map((c) => {
        const last = c.messages[0];
        return {
          id: c.id,
          user: c.user,
          status: c.status,
          lastMessage: last?.text || null,
          lastMessageAt: last?.createdAt || c.createdAt,
        };
      });

      return res.json({
        success: true,
        conversations: shaped,
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin support conversations");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération des conversations support.",
      });
    }
  }
);

// Messages d'une conversation + marquer lus côté admin
app.get(
  "/api/admin/support/conversations/:id/messages",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const conversationId = Number(req.params.id);
      if (Number.isNaN(conversationId)) {
        return res.status(400).json({
          success: false,
          message: "ID de conversation invalide.",
        });
      }

      const conversation = await prisma.supportConversation.findUnique({
        where: { id: conversationId },
        include: {
          user: {
            select: { id: true, fullName: true, phone: true, email: true },
          },
        },
      });

      if (!conversation) {
        return res.status(404).json({
          success: false,
          message: "Conversation introuvable.",
        });
      }

      const messages = await prisma.supportMessage.findMany({
        where: { conversationId },
        orderBy: { createdAt: "asc" },
      });

      // On marque comme lus côté admin tous les messages USER non lus
      await prisma.supportMessage.updateMany({
        where: {
          conversationId,
          sender: SupportSender.USER,
          seenByAdmin: false,
        },
        data: { seenByAdmin: true },
      });

      return res.json({
        success: true,
        conversation: {
          id: conversation.id,
          status: conversation.status,
          user: conversation.user,
        },
        messages,
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin get support messages");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de la récupération des messages support.",
      });
    }
  }
);

app.post(
  "/api/admin/support/conversations/:id/reply",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const conversationId = Number(req.params.id);
      if (Number.isNaN(conversationId)) {
        return res.status(400).json({
          success: false,
          message: "ID de conversation invalide.",
        });
      }

      const { message } = req.body as { message?: string };
      if (!message || message.trim().length < 2) {
        return res.status(400).json({
          success: false,
          message: "Message trop court.",
        });
      }

      const conversation = await prisma.supportConversation.findUnique({
        where: { id: conversationId },
        include: {
          user: true,
        },
      });

      if (!conversation) {
        return res.status(404).json({
          success: false,
          message: "Conversation introuvable.",
        });
      }

      const msg = await prisma.supportMessage.create({
        data: {
          conversationId,
          sender: SupportSender.ADMIN,
          text: message.trim(),
          seenByAdmin: true,
          seenByUser: false,
        },
      });

      // On repasse la convo en OPEN
      await prisma.supportConversation.update({
        where: { id: conversationId },
        data: { status: SupportStatus.OPEN },
      });

      // Notif client (optionnel mais utile)
      try {
        const u = conversation.user;
        if (u.phone) {
          await sendSms(
            u.phone,
            "Smart Business Corp: vous avez reçu une nouvelle réponse de l’assistance dans votre espace client."
          );
          await sendWhatsAppText(
            u.phone,
            "Smart Business Corp\n\nVous avez reçu une nouvelle réponse de l’assistance.\nConnectez-vous à votre espace client pour la consulter."
          );
        }

        if (isEmailEnabled && u.email) {
  await transporter.sendMail({
    from: EMAIL_FROM,
    to: u.email,
    subject: "Nouvelle réponse de l’assistance Smart Business Corp",
    html: `
      <p>Bonjour ${u.fullName},</p>
      <p>Vous avez reçu une nouvelle réponse de l’assistance Smart Business Corp&nbsp;:</p>
      <blockquote>${escapeHtml(message)}</blockquote>
      <p>Connectez-vous à votre espace client pour continuer la conversation.</p>
    `,
  });
}

      } catch (notifErr) {
        console.error("Erreur notif client support:", notifErr);
      }

      return res.json({
        success: true,
        message: msg,
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin reply support");
      return res.status(500).json({
        success: false,
        message:
          "Erreur serveur lors de l’envoi de la réponse support.",
      });
    }
  }
);


/* ------------------------------------------------------------------ */
/*                         ADMIN — RETRAITS                           */
/* ------------------------------------------------------------------ */

app.get(
  "/api/admin/withdrawals",
  authMiddleware,
  adminMiddleware,
  async (req: AuthRequest, res: Response) => {
    try {
      const status = (req.query.status as string) || "PENDING";

      const withdrawals = await prisma.withdrawal.findMany({
        where: status === "ALL" ? {} : { status },
        orderBy: { createdAt: "desc" },
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
            },
          },
        },
      });

      return res.json({
        success: true,
        withdrawals,
      });
    } catch (err) {
      logger.error({ err }, "Erreur admin list withdrawals");
      return res.status(500).json({
        success: false,
        message: "Erreur serveur lors de la récupération des retraits.",
      });
    }
  }
);

/**
 * Handler partagé PATCH/POST pour changer le statut d’un retrait
 * - Transactionnelle (wallet + ledger)
 * - Notifications internes
 * - Push vers l'utilisateur
 */
async function updateWithdrawalStatusHandler(
  req: AuthRequest,
  res: Response
) {
  try {
    const adminId = req.user!.id;
    const id = Number(req.params.id);

    if (Number.isNaN(id)) {
      return res.status(400).json({
        success: false,
        message: "ID de retrait invalide.",
      });
    }

    const newStatus = (req.body.status as string) || "";
    const allowedStatuses = ["PENDING", "PROCESSED", "REJECTED"] as const;

    if (!newStatus || !allowedStatuses.includes(newStatus as any)) {
      return res.status(400).json({
        success: false,
        message:
          "Statut invalide. Valeurs possibles : PENDING, PROCESSED, REJECTED.",
      });
    }

    const { updated, oldStatus } = await prisma.$transaction(async (tx) => {
      const withdrawal = await tx.withdrawal.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
            },
          },
        },
      });

      if (!withdrawal) {
        throw new Error("NOT_FOUND");
      }

      const processedAt =
        newStatus === "PROCESSED" ? new Date() : withdrawal.processedAt;

      const updated = await tx.withdrawal.update({
        where: { id },
        data: {
          status: newStatus,
          processedAt,
        },
        include: {
          user: {
            select: {
              id: true,
              fullName: true,
              phone: true,
            },
          },
        },
      });

      // Si on passe à PROCESSED pour la première fois → débit du wallet + ledger
      if (newStatus === "PROCESSED" && withdrawal.status !== "PROCESSED") {
        await tx.wallet.upsert({
          where: { userId: updated.userId },
          update: {
            balance: { decrement: updated.amount },
          },
          create: {
            userId: updated.userId,
            balance: -updated.amount,
          },
        });

        await tx.ledgerEntry.create({
          data: {
            userId: updated.userId,
            type: "DEBIT",
            amount: updated.amount,
            source: "WITHDRAWAL_PROCESSED",
            reference: `WITHDRAWAL#${updated.id}`,
          },
        });
      }

      return { updated, oldStatus: withdrawal.status };
    });

    logger.info(
      {
        adminId,
        withdrawalId: id,
        oldStatus,
        newStatus,
      },
      "[ADMIN] Statut retrait modifié (transactionnelle)"
    );

    // 💰 Texte lisible du montant
    const amountTxt =
      updated.amount != null
        ? updated.amount.toLocaleString("fr-FR")
        : undefined;

    // 🔔 Notifications + PUSH
    if (newStatus === "PROCESSED") {
      await createNotificationForUser({
        userId: updated.userId,
        type: "WITHDRAWAL_STATUS",
        title: "Retrait validé ✅",
        message: amountTxt
          ? `Votre retrait de ${amountTxt} XOF a été traité avec succès.`
          : "Votre retrait a été traité avec succès.",
      });

      await sendPushToUser(updated.userId, {
        title: "Retrait validé ✅",
        body: amountTxt
          ? `Votre retrait de ${amountTxt} XOF a été traité avec succès.`
          : "Votre retrait a été traité avec succès.",
        url: "https://smartbusinesscorp.org/notifications",
      });
    } else if (newStatus === "REJECTED") {
      await createNotificationForUser({
        userId: updated.userId,
        type: "WITHDRAWAL_STATUS",
        title: "Retrait refusé ❌",
        message:
          "Votre demande de retrait a été refusée. Consultez l’assistance pour plus de détails.",
      });

      await sendPushToUser(updated.userId, {
        title: "Retrait refusé ❌",
        body:
          "Votre demande de retrait a été refusée. Consultez la section Assistance pour plus de détails.",
        url: "https://smartbusinesscorp.org/notifications",
      });
    }

    return res.json({
      success: true,
      withdrawal: updated,
    });
  } catch (err: any) {
    if (err?.message === "NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "Retrait introuvable.",
      });
    }

    logger.error({ err }, "Erreur admin update withdrawal status");
    return res.status(500).json({
      success: false,
      message: "Erreur serveur lors de la mise à jour du retrait.",
    });
  }
}

app.patch(
  "/api/admin/withdrawals/:id/status",
  authMiddleware,
  adminMiddleware,
  updateWithdrawalStatusHandler
);

// Pour compatibilité si le front envoie un POST
app.post(
  "/api/admin/withdrawals/:id/status",
  authMiddleware,
  adminMiddleware,
  updateWithdrawalStatusHandler
);


/* ------------------------------------------------------------------ */
/*                         ERREURS / SENTRY                            */
/* ------------------------------------------------------------------ */

app.use(Sentry.expressErrorHandler() as express.ErrorRequestHandler);

app.use(
  (
    err: any,
    req: Request,
    res: Response,
    _next: NextFunction // eslint-disable-line
  ) => {
    const bodyForLog: any = { ...req.body };

    // 🔒 Masquage des champs sensibles
    const SENSITIVE_KEYS = [
      "password",
      "confirmPassword",
      "currentPassword",
      "newPassword",
      "securityAnswer",
    ];

    for (const key of SENSITIVE_KEYS) {
      if (typeof bodyForLog[key] !== "undefined") {
        bodyForLog[key] = "***redacted***";
      }
    }

    // 🔒 Masquer aussi les en-têtes sensibles
    const headersForLog: any = { ...req.headers };
    if (headersForLog.authorization) {
      headersForLog.authorization = "***redacted***";
    }
    if (headersForLog.cookie) {
      headersForLog.cookie = "***redacted***";
    }
    if (headersForLog["x-api-key"]) {
      headersForLog["x-api-key"] = "***redacted***";
    }

    const requestId = (req as any).requestId;

    logger.error(
      {
        err,
        path: req.path,
        method: req.method,
        body: bodyForLog,
        query: req.query,
        headers: headersForLog,
        requestId,
      },
      "Erreur non gérée"
    );

    res
      .status(500)
      .json({ success: false, message: "Erreur serveur, réessayez plus tard." });
  }
);

/* ------------------------------------------------------------------ */
/*                          404 & ERROR HANDLERS                       */
/* ------------------------------------------------------------------ */

// 404 pour les routes inconnues
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: "Route introuvable.",
  });
});

// Handler d’erreur générique
// (ne PAS renvoyer l’erreur brute en prod)
app.use(
  (
    err: any,
    req: Request,
    res: Response,
    _next: NextFunction
  ) => {
    logger.error(
      {
        err,
        path: req.path,
        method: req.method,
      },
      "Erreur non gérée"
    );

    if (res.headersSent) {
      return;
    }

    res.status(500).json({
      success: false,
      message:
        "Une erreur interne est survenue. L'équipe technique a été notifiée.",
    });
  }
);

// ---------------------------------------------------------------------
//  PUSH NOTIFICATIONS
// ---------------------------------------------------------------------

// Récupérer la clé publique (le front en a besoin)
app.get("/api/push/public-key", (req, res) => {
  res.json({ publicKey: getVapidPublicKey() });
});

// Enregistrer une subscription
app.post("/api/push/subscribe", authMiddleware, async (req, res) => {
  try {
    const userId = (req as any).user.id; // adapte à ton système
    await saveSubscriptionForUser(userId, req.body);
    return res.json({ success: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false });
  }
});

/* ------------------------------------------------------------------ */
/*                               LISTEN                                */
/* ------------------------------------------------------------------ */

app.listen(PORT, () => {
  logger.info(`🚀 API Smart Business Corp démarrée sur le port ${PORT}`);
});
