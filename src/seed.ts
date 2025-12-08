
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main(){
  const tiers=[10000,25000,50000,100000,250000,500000];
  for(const t of tiers){
    await prisma.tier.create({data:{amountXOF:t}});
  }
  console.log("seed completed");
}

main();
