"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// scripts/generate-vapid.ts
const web_push_1 = __importDefault(require("web-push"));
const { publicKey, privateKey } = web_push_1.default.generateVAPIDKeys();
console.log("VAPID_PUBLIC_KEY=", publicKey);
console.log("VAPID_PRIVATE_KEY=", privateKey);
