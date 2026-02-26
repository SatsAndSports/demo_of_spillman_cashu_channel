import express from "express";
import figlet from "figlet";
import { randomBytes } from "crypto";
import { ConfigurableSpilman, mapErrorStatus } from "cdk-spilman-kit";

// ============================================================================
// Configuration
// ============================================================================

export const SECRET_KEY = process.env.SERVER_SECRET_KEY || randomBytes(32).toString("hex");
export const CONFIG_PATH = process.env.CONFIG_PATH || "config.yaml";
const PORT = parseInt(process.env.PORT || "5002", 10);

// ============================================================================
// Main Entry Point
// ============================================================================

export async function startServer(): Promise<void> {
  console.log("=".repeat(60));
  console.log("ASCII Art Server - Spilman Payment Channel Demo (TypeScript)");
  console.log("=".repeat(60));
  console.log();

  // Bootstrap Spilman components from YAML
  const spilmanCtx = await ConfigurableSpilman.fromYaml(CONFIG_PATH, SECRET_KEY);
  const { spilman, router, config, stores } = spilmanCtx;

  const app = express();
  app.use(express.json());

  // Management routes: /channel/params, /channel/register, etc.
  app.use("/channel", router);

  // POST /ascii - Generate ASCII art (requires payment)
  app.post("/ascii", (req, res) => {
    const message = req.body?.message;
    if (!message) {
      res.status(400).json({ error: "Missing 'message' in request body" });
      return;
    }

    console.log(`\n[Request] ASCII art for '${message}' (${message.length} chars)`);

    let paymentInfo: any;
    try {
      // Pass usage increments in the context
      paymentInfo = spilman.processRequestPayment(req, { chars: message.length });
    } catch (e) {
      const errorMsg = (e as Error).message || String(e);
      console.log(`  [Payment] REJECTED: ${errorMsg}`);

      const status = mapErrorStatus(errorMsg);

      res.setHeader("X-Cashu-Channel", JSON.stringify({ error: errorMsg }));
      res.status(status).json({ error: "Payment failed", reason: errorMsg });
      return;
    }

    console.log(`  [Payment] ACCEPTED: balance=${paymentInfo.balance}/${paymentInfo.capacity}`);

    const art = figlet.textSync(message);

    spilman.attachPaymentHeader(res, paymentInfo).json({
      art,
      message,
      payment: paymentInfo,
    });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server pubkey: ${spilmanCtx.host.serverPubkey}`);
    console.log(`Mints:         ${Object.keys(config.mints).join(", ")}`);
    
    // Display active pricing
    const activeUnits = stores.keysetCache.getActiveUnits();
    const pricingStr = Object.entries(config.pricing)
      .filter(([unit]) => activeUnits.has(unit))
      .map(([unit, p]) => {
        const vars = Object.entries(p.variables).map(([v, price]) => `${price}/${v}`).join("+");
        return `${unit}=${vars}`;
      })
      .join(", ");
      
    console.log(`Pricing:       ${pricingStr || '(no active units)'}`);
    console.log(`Listening on:  http://0.0.0.0:${PORT}`);
    console.log();
    console.log("Endpoints:");
    console.log(`  GET  http://localhost:${PORT}/channel/params`);
    console.log(`  POST http://localhost:${PORT}/channel/register`);
    console.log(`  POST http://localhost:${PORT}/ascii`);
    console.log();
    console.log("=".repeat(60));
    console.log();

    const shutdown = () => {
      console.log("\n[Shutdown] Received signal, exiting...");
      process.exit(0);
    };
    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);
  });
}
