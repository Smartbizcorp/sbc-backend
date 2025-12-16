-- CreateTable
CREATE TABLE IF NOT EXISTS "TranslationCache" (
  "id" SERIAL NOT NULL,
  "locale" TEXT NOT NULL,
  "hash" TEXT NOT NULL,
  "source" TEXT NOT NULL,
  "target" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "TranslationCache_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "TranslationCache_hash_key" ON "TranslationCache"("hash");
