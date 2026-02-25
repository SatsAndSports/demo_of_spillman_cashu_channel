import * as secp from "@noble/secp256k1";
import { compute_channel_secret, sign_with_tweaked_key } from "../wasm/cdk_wasm.js";
import { PricingTable, SpilmanStores } from "./stores.js";

export interface SpilmanHostOptions {
  secretKeyHex: string;
  mintUrl: string;
  pricing: PricingTable;
  stores: SpilmanStores;
  refreshKeysets?: (mint: string) => Promise<void>;
}

export function getServerPubkey(secretKeyHex: string): string {
  const secretBytes = Buffer.from(secretKeyHex, "hex");
  const pubkeyBytes = secp.getPublicKey(secretBytes, true);
  return Buffer.from(pubkeyBytes).toString("hex");
}

export function createSpilmanHost(options: SpilmanHostOptions) {
  const { secretKeyHex, mintUrl, pricing, stores, refreshKeysets } = options;
  const receiverPubkey = getServerPubkey(secretKeyHex);
  const normalizedMint = mintUrl.replace(/\/$/, "");

  return {
    receiverKeyIsAcceptable: (pubkeyHex: string): boolean => {
      return pubkeyHex.toLowerCase() === receiverPubkey.toLowerCase();
    },

    mintAndKeysetIsAcceptable: (mint: string, keysetId: string): boolean => {
      const normMint = mint.replace(/\/$/, "");
      return normMint === normalizedMint && stores.keysetCache.has(mint, keysetId);
    },

    getFundingAndParams: (channelId: string): [string, string, string, string] | null => {
      const funding = stores.channelFunding.get(channelId);
      if (!funding) return null;
      return [
        funding.paramsJson,
        funding.fundingProofsJson,
        funding.channelSecret,
        funding.keysetInfoJson,
      ];
    },

    saveFunding: (
      channelId: string,
      paramsJson: string,
      fundingProofsJson: string,
      channelSecret: string,
      keysetInfoJson: string,
      initialBalance: number,
      initialSignature: string
    ): void => {
      stores.channelFunding.insert(channelId, {
        paramsJson,
        fundingProofsJson,
        channelSecret,
        keysetInfoJson,
      });
      stores.channelBalance.update(channelId, Number(initialBalance), initialSignature);
    },

    getAmountDue: (channelId: string, contextJson: string | null): bigint => {
      const usage = stores.channelUsage.get(channelId);
      let totalChars = usage?.charsServed ?? 0;

      if (contextJson) {
        const context = JSON.parse(contextJson);
        totalChars += context.message_length || 0;
      }

      const funding = stores.channelFunding.get(channelId);
      if (!funding) return BigInt(0);

      const params = JSON.parse(funding.paramsJson);
      const unitPricing = pricing[params.unit];
      if (!unitPricing) return BigInt(0);

      return BigInt(totalChars * unitPricing.per_char);
    },

    recordPayment: (channelId: string, balance: number, signature: string, contextJson: string): void => {
      const context = JSON.parse(contextJson);
      const messageLength = context.message_length || 0;
      stores.channelUsage.recordCharsServed(channelId, messageLength);
      stores.channelBalance.update(channelId, Number(balance), signature);
    },

    getChannelState: (channelId: string): string => {
      if (stores.channelClosed.isClosed(channelId)) return "closed";
      if (stores.channelClosing.isClosing(channelId)) return "closing";
      return "open";
    },

    markChannelClosing: (
      channelId: string,
      locktime: number,
      balance: number,
      signature: string
    ): void => {
      if (stores.channelClosed.isClosed(channelId)) {
        throw new Error("channel already closed");
      }
      stores.channelClosing.markClosing(channelId, Number(locktime), Number(balance), signature);
    },

    getClosingData: (channelId: string): { locktime: number; balance: number; signature: string } | null => {
      return stores.channelClosing.get(channelId);
    },

    getChannelPolicy: (unit: string): { min_expiry_in_seconds: number; min_capacity: number; max_amount_per_output?: number } | null => {
      const unitPricing = pricing[unit];
      if (!unitPricing) return null;
      return {
        min_expiry_in_seconds: 3600,
        min_capacity: unitPricing.minCapacity,
        max_amount_per_output: unitPricing.maxAmountPerOutput,
      };
    },

    nowSeconds: (): bigint => {
      return BigInt(Math.floor(Date.now() / 1000));
    },

    getBalanceAndSignatureForUnilateralExit: (channelId: string): [number, string] | null => {
      const balanceData = stores.channelBalance.get(channelId);
      if (!balanceData) return null;
      return [balanceData.balance, balanceData.signature];
    },

    getActiveKeysetIds: (mint: string, unit: string): string[] => {
      return stores.keysetCache.getActiveIds(mint, unit);
    },

    getKeysetInfo: (mint: string, keysetId: string): string | null => {
      const entry = stores.keysetCache.get(mint, keysetId);
      return entry?.infoJson ?? null;
    },

    callMintSwap: async (mintUrlArg: string, swapRequestJson: string): Promise<string> => {
      const response = await fetch(`${mintUrlArg}/v1/swap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: swapRequestJson,
      });
      if (!response.ok) {
        const text = await response.text();
        return JSON.stringify({ error: `Mint rejected swap: ${text}` });
      }
      return await response.text();
    },

    markChannelClosed: (
      channelId: string,
      locktime: number,
      balance: number,
      receiverProofsJson: string,
      senderProofsJson: string,
      receiverSum: number,
      senderSum: number
    ): void => {
      if (stores.channelClosed.isClosed(channelId)) {
        throw new Error("channel already closed");
      }
      stores.channelClosed.markClosed(
        channelId,
        Number(locktime),
        Number(balance),
        Number(receiverSum) + Number(senderSum),
        Number(receiverSum),
        Number(senderSum),
        receiverProofsJson,
        senderProofsJson
      );
    },

    refreshAllKeysets: async (mint: string): Promise<void> => {
      if (!refreshKeysets) return;
      await refreshKeysets(mint);
    },

    computeChannelSecret: (_charliePubkeyHex: string, alicePubkeyHex: string): string => {
      return compute_channel_secret(secretKeyHex, alicePubkeyHex);
    },

    signWithTweakedKey: (_signerPubkeyHex: string, messageHex: string, tweakScalarHex: string): string => {
      return sign_with_tweaked_key(secretKeyHex, messageHex, tweakScalarHex);
    },
  };
}
