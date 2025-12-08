import logger from "../logger";

/* -------------------------------------------------------
   🧩 Twilio optional-import (no crash if module missing)
-------------------------------------------------------- */
let twilioClient: any = null;

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_FROM_NUMBER,
  ADMIN_PHONE,
} = process.env;

try {
  // Charge Twilio uniquement si installé
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const twilio = require("twilio");

  if (TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
    twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    logger.info("📨 Twilio initialisé.");
  } else {
    logger.warn(
      "⚠️ TWILIO_ACCOUNT_SID ou TWILIO_AUTH_TOKEN manquant. Les SMS seront désactivés."
    );
  }
} catch (err) {
  logger.warn(
    "⚠️ Module 'twilio' non installé. Les SMS sont désactivés. Installe-le avec : npm install twilio"
  );
}

/* -------------------------------------------------------
   📤 Envoi SMS
-------------------------------------------------------- */
export async function sendSms(to: string, body: string): Promise<void> {
  if (!twilioClient || !TWILIO_FROM_NUMBER) {
    logger.warn(
      { to, body },
      "sendSms appelé mais Twilio n'est pas disponible ou mal configuré."
    );
    return;
  }

  try {
    await twilioClient.messages.create({
      to,
      from: TWILIO_FROM_NUMBER,
      body,
    });

    logger.info({ to }, "📨 SMS envoyé avec succès.");
  } catch (err) {
    logger.error({ err, to }, "❌ Erreur envoi SMS");
  }
}

/* -------------------------------------------------------
   📢 Notifier l’admin automatiquement
-------------------------------------------------------- */
export async function notifyAdminSms(body: string): Promise<void> {
  if (!ADMIN_PHONE) {
    logger.warn(
      "⚠️ ADMIN_PHONE non configuré — impossible d'envoyer une alerte SMS admin."
    );
    return;
  }
  await sendSms(ADMIN_PHONE, body);
}
