import { Request, Response } from "express";
import { WasmSpilmanBridge } from "../wasm/cdk_wasm.js";

export interface SpilmanPaymentResult {
  channel_id: string;
  balance: number;
  amount_due: number;
  capacity: number;
}

export function decodePaymentHeader(header: string): string {
  // Validate base64 format
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(header)) {
    throw new Error("invalid base64 encoding");
  }
  return Buffer.from(header, "base64").toString("utf-8");
}

export function mapErrorStatus(errorMsg: string): number {
  const lowerMsg = errorMsg.toLowerCase();
  if (lowerMsg.includes("channel closed")) return 410;
  if (lowerMsg.includes("channel closing")) return 409;
  
  // Payment Required (402) cases
  const isPaymentRequired = 
    lowerMsg.includes("missing x-cashu-channel") ||
    lowerMsg.includes("invalid signature") ||
    lowerMsg.includes("missing header") ||
    lowerMsg.includes("signature verification failed") ||
    lowerMsg.includes("channel_id mismatch") ||
    lowerMsg.includes("insufficient balance") ||
    lowerMsg.includes("balance exceeds capacity") ||
    lowerMsg.includes("locktime too soon") ||
    lowerMsg.includes("mint or keyset not acceptable") ||
    lowerMsg.includes("max_amount_per_output exceeded");

  if (isPaymentRequired) return 402;
  
  const isBadRequest = 
    lowerMsg.includes("invalid base64") ||
    lowerMsg.includes("invalid utf8") ||
    lowerMsg.includes("invalid json") ||
    lowerMsg.includes("missing field") ||
    lowerMsg.includes("missing channel_id") ||
    lowerMsg.includes("missing signature") ||
    (lowerMsg.includes("expected") && (lowerMsg.includes("string") || lowerMsg.includes("integer") || lowerMsg.includes("u64")));
    
  if (isBadRequest) return 400;
  if (lowerMsg.includes("internal") || lowerMsg.includes("misconfigured")) return 500;
  
  return 402; // Default: Payment Required
}

export { mapErrorStatus as mapBridgeErrorStatus };

export class Spilman {
  constructor(private bridge: WasmSpilmanBridge) {}

  /**
   * Extracts and processes payment from the current Express request.
   * 
   * @param req Express request
   * @param context Object or JSON string containing usage increments
   * @returns SpilmanPaymentResult
   * @throws Error with message that should be mapped to HTTP status
   */
  processRequestPayment(req: Request, context: object | string = {}): SpilmanPaymentResult {
    const headerB64 = req.headers["x-cashu-channel"] as string | undefined;
    if (!headerB64) {
      throw new Error("Missing X-Cashu-Channel header");
    }

    const paymentJson = decodePaymentHeader(headerB64);
    const contextJson = typeof context === "string" ? context : JSON.stringify(context);

    // WASM bridge throws on validation error
    return this.bridge.processPayment(paymentJson, contextJson) as any;
  }

  /**
   * Attaches the confirmation header to an Express response.
   */
  attachPaymentHeader(res: Response, payment: SpilmanPaymentResult): Response {
    const info = {
      channel_id: payment.channel_id,
      balance: payment.balance,
      amount_due: payment.amount_due,
      capacity: payment.capacity,
    };
    res.setHeader("X-Cashu-Channel", JSON.stringify(info));
    return res;
  }
}
