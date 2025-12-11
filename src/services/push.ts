// src/services/push.ts
import webPush from "web-push";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY!;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY!;

webPush.setVapidDetails(
  "mailto:contact@smartbusinesscorp.org",
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

export const getVapidPublicKey = () => VAPID_PUBLIC_KEY;

// Enregistrer une subscription pour un user
export async function saveSubscriptionForUser(
  userId: number,
  subscription: PushSubscriptionJSON
) {
  const { endpoint, keys } = subscription;

  if (!endpoint || !keys?.p256dh || !keys?.auth) return;

  await prisma.pushSubscription.upsert({
    where: { endpoint },
    update: {
      userId,
      p256dh: keys.p256dh,
      auth: keys.auth,
    },
    create: {
      userId,
      endpoint,
      p256dh: keys.p256dh,
      auth: keys.auth,
    },
  });
}

// Envoyer une notif à tous les devices d’un user
export async function sendPushToUser(
  userId: number,
  payload: { title: string; body: string; url?: string }
) {
  const subs = await prisma.pushSubscription.findMany({
    where: { userId },
  });

  const data = JSON.stringify(payload);

  await Promise.all(
    subs.map(async (sub) => {
      try {
        await webPush.sendNotification(
          {
            endpoint: sub.endpoint,
            keys: {
              p256dh: sub.p256dh,
              auth: sub.auth,
            },
          },
          data
        );
      } catch (err: any) {
        // Si l’abonnement est cassé → on le supprime
        if (err?.statusCode === 410 || err?.statusCode === 404) {
          await prisma.pushSubscription.delete({
            where: { endpoint: sub.endpoint },
          });
        } else {
          console.error("Erreur push", err);
        }
      }
    })
  );
}

// Type minimal pour la subscription envoyée par le front
type PushSubscriptionJSON = {
  endpoint: string;
  keys?: {
    p256dh: string;
    auth: string;
  };
};
