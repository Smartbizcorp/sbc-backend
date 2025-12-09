// src/services/notifications.ts
import { PrismaClient } from "@prisma/client";
import logger from "../logger";

const prisma = new PrismaClient();

export type NotificationType =
  | "WITHDRAWAL_STATUS"
  | "INVESTMENT_STATUS";

export async function createNotificationForUser(params: {
  userId: number;
  type: NotificationType;
  title: string;
  message: string;
}) {
  const { userId, type, title, message } = params;

  try {
    await prisma.notification.create({
      data: {
        userId,
        type,
        title,
        message,
      },
    });
  } catch (err) {
    logger.error({ err, userId, type }, "Erreur création notification");
  }
}
