// src/routes/i18nTranslate.ts
import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import rateLimit from "express-rate-limit";
import { createHash } from "crypto";
import logger from "../logger";

const prisma = new PrismaClient();
const router = Router();

/* ------------------------------------------------------------------ */
/*                           Helpers                                   */
/* ------------------------------------------------------------------ */

function sha256(input: string) {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function normalizeLocale(l: string) {
  // DeepL utilise souvent EN/EN-GB/EN-US, FR, etc.
  // On accepte fr, fr-FR, en, en-US...
  return String(l || "")
    .trim()
    .toUpperCase()
    .replace("_", "-");
}

function isLikelyHtml(text: string) {
  return /<\/?[a-z][\s\S]*>/i.test(text);
}

/* ------------------------------------------------------------------ */
/*                           Validation                                */
/* ------------------------------------------------------------------ */

const bodySchema = z.object({
  sourceText: z.string().min(1, "sourceText manquant").max(20000, "Texte trop long"),
  sourceLocale: z.string().optional().default("FR"),
  targetLocale: z.string().min(2, "targetLocale manquant").max(12),
  // optionnel: si tu veux forcer formal/informal
  formality: z.enum(["default", "more", "less"]).optional(),
});

const translateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Trop de requêtes traduction. Réessayez bientôt." },
});

/* ------------------------------------------------------------------ */
/*                     DeepL Provider (API HTTP)                       */
/* ------------------------------------------------------------------ */

async function translateViaDeepL(params: {
  text: string;
  from: string;
  to: string;
  formality?: "default" | "more" | "less";
}) {
  const apiKey = process.env.DEEPL_API_KEY;
  if (!apiKey) {
    throw new Error("DEEPL_API_KEY manquant (.env)");
  }

  // Free vs Pro : url différente
  const base =
    process.env.DEEPL_API_URL ||
    (String(apiKey).endsWith(":fx")
      ? "https://api-free.deepl.com/v2/translate"
      : "https://api.deepl.com/v2/translate");

  const sourceLang = normalizeLocale(params.from);
  const targetLang = normalizeLocale(params.to);

  // DeepL n’accepte pas forcément FR-FR: on simplifie "FR-FR" -> "FR"
  const safeSource = sourceLang.split("-")[0];
  const safeTarget = targetLang; // EN-US / EN-GB OK, sinon EN

  const form = new URLSearchParams();
  form.append("text", params.text);
  form.append("target_lang", safeTarget);
  if (safeSource) form.append("source_lang", safeSource);

  // Détecte si HTML
  if (isLikelyHtml(params.text)) {
    form.append("tag_handling", "html");
  }

  // Formality (DeepL Pro + langues compatibles)
  if (params.formality && params.formality !== "default") {
    form.append("formality", params.formality);
  }

  const res = await fetch(base, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `DeepL-Auth-Key ${apiKey}`,
    },
    body: form.toString(),
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    throw new Error(
      `DeepL error (${res.status}) ${errText ? `: ${errText}` : ""}`.trim()
    );
  }

  const json: any = await res.json();
  const translated = json?.translations?.[0]?.text;
  if (!translated) throw new Error("DeepL: réponse invalide (pas de texte).");

  return String(translated);
}

/* ------------------------------------------------------------------ */
/*                          ROUTE                                      */
/* ------------------------------------------------------------------ */
/**
 * POST /api/i18n/translate
 * Body: { sourceText, sourceLocale?, targetLocale, formality? }
 *
 * Cache: table TranslationCache (hash unique)
 */
router.post("/i18n/translate", translateLimiter, async (req: Request, res: Response) => {
  try {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) {
      const msg = parsed.error.issues?.[0]?.message ?? "Paramètres invalides";
      return res.status(400).json({ success: false, message: msg });
    }

    const sourceText = parsed.data.sourceText.trim();
    const sourceLocale = normalizeLocale(parsed.data.sourceLocale || "FR");
    const targetLocale = normalizeLocale(parsed.data.targetLocale);
    const formality = parsed.data.formality;

    // Pas de traduction si même langue
    if (sourceLocale === targetLocale || sourceLocale.split("-")[0] === targetLocale.split("-")[0]) {
      return res.json({ success: true, translated: sourceText, cached: true });
    }

    // Hash stable (langues + texte + formality)
    const hash = sha256(`${sourceLocale}→${targetLocale}::${formality ?? "default"}::${sourceText}`);

    // 1) Cache hit
    const cached = await prisma.translationCache.findUnique({ where: { hash } });
    if (cached?.target) {
      return res.json({ success: true, translated: cached.target, cached: true });
    }

    // 2) Traduction DeepL
    const translated = await translateViaDeepL({
      text: sourceText,
      from: sourceLocale,
      to: targetLocale,
      formality,
    });

    // 3) Save cache (upsert pour éviter collisions)
    await prisma.translationCache.upsert({
      where: { hash },
      update: { target: translated, locale: targetLocale },
      create: {
        locale: targetLocale,
        hash,
        source: sourceText,
        target: translated,
      },
    });

    logger.info(
      { sourceLocale, targetLocale, cached: false, size: sourceText.length },
      "[I18N] translation created"
    );

    return res.json({ success: true, translated, cached: false });
  } catch (err: any) {
    logger.error({ err }, "[I18N] translate error");
    return res.status(500).json({
      success: false,
      message: err?.message || "Erreur serveur traduction",
    });
  }
});

export default router;
