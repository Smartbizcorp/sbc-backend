// scripts/generate-vapid.ts
import webPush from "web-push";

const { publicKey, privateKey } = webPush.generateVAPIDKeys();

console.log("VAPID_PUBLIC_KEY=", publicKey);
console.log("VAPID_PRIVATE_KEY=", privateKey);
