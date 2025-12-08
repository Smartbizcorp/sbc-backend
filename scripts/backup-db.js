// scripts/backup-db.js
const fs = require("fs");
const path = require("path");

// chemin de la base SQLite actuelle (prisma => file:dev.db)
const dbPath = path.join(__dirname, "..", "prisma", "dev.db");

// dossier de destination des backups
const backupDir = path.join(__dirname, "..", "backups");

// s'assurer que le dossier backups existe
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

// générer un nom de fichier avec timestamp
const now = new Date();
const pad = (n) => n.toString().padStart(2, "0");

const stamp = [
  now.getFullYear(),
  pad(now.getMonth() + 1),
  pad(now.getDate()),
  "_",
  pad(now.getHours()),
  pad(now.getMinutes()),
  pad(now.getSeconds()),
].join("");

const backupFile = path.join(backupDir, `dev-backup-${stamp}.db`);

fs.copyFile(dbPath, backupFile, (err) => {
  if (err) {
    console.error("❌ Erreur lors de la sauvegarde de la base :", err);
    process.exit(1);
  }
  console.log("✅ Sauvegarde terminée :", backupFile);
  process.exit(0);
});
