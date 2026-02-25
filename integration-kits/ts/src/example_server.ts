import express from "express";
import figlet from "figlet";
import { randomBytes } from "crypto";
import { WasmSpilmanBridge } from "../wasm/cdk_wasm.js";
import { createSpilmanHost, getServerPubkey } from "./host.js";
import { createSpilmanManagementRouter } from "./router.js";
import { createInMemoryStores, getActivePricing, PricingTable } from "./stores.js";
import { fetchAndCacheKeysetsForMint } from "./keysets.js";

const SECRET_KEY = process.env.SERVER_SECRET_KEY || randomBytes(32).toString("hex");
const MINT_URL = process.env.MINT_URL || "http://localhost:3338";
const PORT = parseInt(process.env.PORT || "5002", 10);

const PRICING: PricingTable = {
  sat: { per_char: 1, minCapacity: 10 },
  msat: { per_char: 1000, minCapacity: 10000 },
  usd: { per_char: 1, minCapacity: 10, maxAmountPerOutput: 64 },
};

const stores = createInMemoryStores();
const receiverPubkey = getServerPubkey(SECRET_KEY);

const host = createSpilmanHost({
  secretKeyHex: SECRET_KEY,
  mintUrl: MINT_URL,
  pricing: PRICING,
  stores,
  refreshKeysets: async (mint: string) => {
    await fetchAndCacheKeysetsForMint(mint, PRICING, stores.keysetCache);
  },
});

const bridge = new WasmSpilmanBridge(host);

async function initializeKeysets(): Promise<void> {
  try {
    await fetchAndCacheKeysetsForMint(MINT_URL, PRICING, stores.keysetCache);
  } catch (e) {
    console.error(`WARNING: Failed to fetch keysets: ${e}`);
  }
}

function decodePaymentHeader(header: string): string {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(header)) {
    throw new Error("invalid base64 encoding");
  }
  return Buffer.from(header, "base64").toString("utf-8");
}

export async function startServer(): Promise<void> {
  await initializeKeysets();

  const app = express();
  app.use(express.json());

  app.use(
    "/channel",
    createSpilmanManagementRouter({
      bridge,
      receiverPubkey,
      pricing: PRICING,
      stores,
      getActivePricing: () => getActivePricing(PRICING, stores.keysetCache),
    })
  );

  app.post("/ascii", (req, res) => {
    const paymentHeaderB64 = req.headers["x-cashu-channel"] as string | undefined;
    if (!paymentHeaderB64) {
      res.status(402).json({
        error: "Payment required",
        reason: "Missing X-Cashu-Channel header",
      });
      return;
    }

    let paymentJson: string;
    try {
      paymentJson = decodePaymentHeader(paymentHeaderB64);
    } catch {
      res.status(400).json({
        error: "Invalid payment header",
        reason: "invalid base64 encoding",
      });
      return;
    }

    const message = req.body?.message;
    if (!message) {
      res.status(400).json({ error: "Missing 'message' in request body" });
      return;
    }

    const context = JSON.stringify({ message_length: message.length });

    let paymentInfo: { channel_id: string; balance: number; amount_due: number; capacity: number };
    try {
      paymentInfo = bridge.processPayment(paymentJson, context) as any;
    } catch (e) {
      const errorMsg = (e as Error).message || String(e);
      let status = 402;
      const lowerMsg = errorMsg.toLowerCase();
      if (lowerMsg.includes("channel closed")) {
        status = 410;
      } else if (lowerMsg.includes("channel closing")) {
        status = 409;
      } else if (
        lowerMsg.includes("invalid base64") ||
        lowerMsg.includes("invalid utf8") ||
        lowerMsg.includes("invalid json") ||
        lowerMsg.includes("missing field") ||
        lowerMsg.includes("missing channel_id") ||
        lowerMsg.includes("missing signature") ||
        (lowerMsg.includes("expected") &&
          (lowerMsg.includes("string") || lowerMsg.includes("integer") || lowerMsg.includes("u64")))
      ) {
        status = 400;
      } else if (lowerMsg.includes("internal") || lowerMsg.includes("misconfigured")) {
        status = 500;
      }
      res.setHeader("X-Cashu-Channel", JSON.stringify({ error: errorMsg }));
      res.status(status).json({ error: "Payment failed", reason: errorMsg });
      return;
    }

    const funding = stores.channelFunding.get(paymentInfo.channel_id);
    const channelParams = funding ? JSON.parse(funding.paramsJson) : null;
    const unitPricing = channelParams ? PRICING[channelParams.unit] : PRICING.sat;
    const cost = message.length * (unitPricing?.per_char ?? 1);

    const art = figlet.textSync(message);
    res.json({
      art,
      message,
      cost,
      payment: paymentInfo,
    });
  });

  app.listen(PORT, "0.0.0.0", () => {
    const activePricing = getActivePricing(PRICING, stores.keysetCache);
    const pricingStr = Object.entries(activePricing)
      .map(([unit, p]) => `${unit}=${p.per_char}/char`)
      .join(", ");
    console.log(`Server pubkey: ${receiverPubkey}`);
    console.log(`Mint URL: ${MINT_URL}`);
    console.log(`Pricing: ${pricingStr || "(no active units)"}`);
    console.log(`Listening on: http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((e) => {
  console.error(e);
  process.exit(1);
});
