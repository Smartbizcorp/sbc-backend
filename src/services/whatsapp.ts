// backend/src/services/whatsapp.ts
import logger from "../logger";

// ✅ On utilise le fetch global (Node 18+)
// Si ton TS ne connaît pas fetch, ceci évite les erreurs de typage :
declare const fetch: any;

const {
  WHATSAPP_TOKEN,
  WHATSAPP_PHONE_NUMBER_ID,
  ADMIN_WHATSAPP,
} = process.env;

const WHATSAPP_API_BASE = "https://graph.facebook.com/v20.0";

if (!WHATSAPP_TOKEN || !WHATSAPP_PHONE_NUMBER_ID) {
  logger.warn(
    "⚠️ WHATSAPP_TOKEN ou WHATSAPP_PHONE_NUMBER_ID manquant. Les messages WhatsApp ne seront pas envoyés."
  );
}

/**
 * Envoie un simple texte WhatsApp (message de service, pas marketing).
 * @param to Numéro au format international, ex: 221771234567
 * @param body Texte du message
 */
export async function sendWhatsAppText(to: string, body: string): Promise<void> {
  if (!WHATSAPP_TOKEN || !WHATSAPP_PHONE_NUMBER_ID) {
    logger.warn(
      { to, body },
      "sendWhatsAppText appelé mais WhatsApp Cloud API n'est pas configuré."
    );
    return;
  }

  try {
    const url = `${WHATSAPP_API_BASE}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

    const payload = {
      messaging_product: "whatsapp",
      to, // numéro client/admin
      type: "text",
      text: {
        body,
      },
    };

    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WHATSAPP_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      logger.error(
        {
          status: res.status,
          statusText: res.statusText,
          body: text,
        },
        "Erreur WhatsApp Cloud API"
      );
      return;
    }

    logger.info({ to }, "Message WhatsApp envoyé avec succès.");
  } catch (err) {
    logger.error({ err, to }, "Erreur lors de l'envoi du message WhatsApp");
  }
}

/**
 * Helper pour notifier l'admin sur WhatsApp (via ADMIN_WHATSAPP)
 */
export async function notifyAdminWhatsApp(
  body: string
): Promise<void> {
  if (!ADMIN_WHATSAPP) {
    logger.warn(
      "ADMIN_WHATSAPP non configuré, impossible d'envoyer le WhatsApp admin."
    );
    return;
  }

  await sendWhatsAppText(ADMIN_WHATSAPP, body);
}
