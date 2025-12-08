// src/config/jwt.ts
import logger from "../logger";

export const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  logger.error("JWT_SECRET manquant dans les variables d'environnement (.env).");
  throw new Error("JWT_SECRET manquant dans les variables d'environnement (.env).");
}
