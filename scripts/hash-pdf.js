const fs = require("fs");
const crypto = require("crypto");

const filePath = process.argv[2];

if (!filePath) {
  console.error("❌ Usage: node hash-pdf.js chemin/vers/fichier.pdf");
  process.exit(1);
}

const fileBuffer = fs.readFileSync(filePath);

const hash = crypto
  .createHash("sha256")
  .update(fileBuffer)
  .digest("hex");

console.log("✅ SHA-256 :", hash);
