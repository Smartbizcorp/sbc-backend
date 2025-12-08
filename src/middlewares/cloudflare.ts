// middlewares/cloudflare.ts
import rateLimit from "express-rate-limit";
import { Request, Response, NextFunction } from "express";
import logger from "../logger";

// On se base sur l'IP réelle fournie par Cloudflare
function getClientIp(req: Request): string {
  const cfIp = (req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "") as string;

  // x-forwarded-for peut contenir une liste
  return cfIp.split(",")[0].trim();
}

// Petit middleware de log + hard-block basique
export function cloudflareGuard(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const ip = getClientIp(req);
  const cfCountry = req.headers["cf-ipcountry"] as string | undefined;
  const ua = req.headers["user-agent"] || "unknown";

  // Exemple : si tu veux bloquer certains user-agents pourris :
  if (ua.includes("sqlmap") || ua.includes("nikto")) {
    logger.warn({ ip, ua }, "User-agent malveillant bloqué");
    return res.status(403).json({
      success: false,
      message: "Accès refusé.",
    });
  }

  // Tu peux aussi ajouter un blocage de pays si besoin, par ex :
  // if (cfCountry && !["SN", "CI", "FR"].includes(cfCountry)) { ... }

  (req as any).realIp = ip;
  next();
}

// Rate limiter basé sur l'IP Cloudflare
export const cloudflareRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // 120 requêtes / minute / IP (à ajuster)
  keyGenerator: (req) => {
    const ip =
      (req as any).realIp ||
      (req.headers["cf-connecting-ip"] as string) ||
      req.ip;
    return ip;
  },
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      "Trop de requêtes depuis cette adresse IP. Merci de réessayer un peu plus tard.",
  },
});
