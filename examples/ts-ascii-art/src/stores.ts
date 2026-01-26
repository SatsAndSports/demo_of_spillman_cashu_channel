/**
 * In-memory stores for Spilman channel state.
 * 
 * These stores track channel funding, usage, balances, and closed status.
 * In production, you'd persist these to a database.
 */

// ============================================================================
// Type Definitions
// ============================================================================

export interface ChannelFundingData {
  paramsJson: string;
  fundingProofsJson: string;
  sharedSecret: string;
  keysetInfoJson: string;
}

export interface ChannelBalance {
  balance: number;
  signature: string;
}

export interface ChannelUsage {
  charsServed: number;
}

export interface ClosedChannelData {
  locktime: number;
  closedAmount: number;
  valueAfterStage1: number;
  receiverSum: number;
  receiverProofsJson: string;
  senderProofsJson: string;
}

export interface KeysetCacheEntry {
  infoJson: string;
  active: boolean;
  unit: string;
}

// ============================================================================
// Channel Funding Store
// ============================================================================

const channelFundingStore = new Map<string, ChannelFundingData>();

export const channelFunding = {
  get(channelId: string): ChannelFundingData | null {
    return channelFundingStore.get(channelId) ?? null;
  },

  insert(channelId: string, data: ChannelFundingData): void {
    if (!channelFundingStore.has(channelId)) {
      channelFundingStore.set(channelId, data);
      console.log(`  [Store] Saved funding for channel ${channelId.substring(0, 8)}...`);
    }
  },

  all(): Map<string, ChannelFundingData> {
    return channelFundingStore;
  },
};

// ============================================================================
// Channel Balance Store
// ============================================================================

const channelBalanceStore = new Map<string, ChannelBalance>();

export const channelBalance = {
  get(channelId: string): ChannelBalance | null {
    return channelBalanceStore.get(channelId) ?? null;
  },

  update(channelId: string, balance: number, signature: string): void {
    const current = channelBalanceStore.get(channelId);
    if (!current || balance > current.balance) {
      channelBalanceStore.set(channelId, { balance, signature });
      console.log(`  [Store] Balance updated: channel=${channelId.substring(0, 8)} ${current?.balance ?? 0} -> ${balance}`);
    }
  },
};

// ============================================================================
// Channel Usage Store
// ============================================================================

const channelUsageStore = new Map<string, ChannelUsage>();

export const channelUsage = {
  get(channelId: string): ChannelUsage | null {
    return channelUsageStore.get(channelId) ?? null;
  },

  recordCharsServed(channelId: string, chars: number): void {
    let usage = channelUsageStore.get(channelId);
    if (!usage) {
      usage = { charsServed: 0 };
      channelUsageStore.set(channelId, usage);
    }
    usage.charsServed += chars;
    console.log(`  [Store] Usage: channel=${channelId.substring(0, 8)} chars=${usage.charsServed}`);
  },
};

// ============================================================================
// Channel Closed Store
// ============================================================================

const channelClosedStore = new Map<string, ClosedChannelData>();

export const channelClosed = {
  isClosed(channelId: string): boolean {
    return channelClosedStore.has(channelId);
  },

  markClosed(
    channelId: string,
    locktime: number,
    closedAmount: number,
    valueAfterStage1: number,
    receiverSum: number,
    receiverProofsJson: string,
    senderProofsJson: string
  ): void {
    channelClosedStore.set(channelId, {
      locktime,
      closedAmount,
      valueAfterStage1,
      receiverSum,
      receiverProofsJson,
      senderProofsJson,
    });
    console.log(`  [Store] Channel closed: ${channelId.substring(0, 8)} amount=${closedAmount} value=${valueAfterStage1}`);
  },

  get(channelId: string): ClosedChannelData | null {
    return channelClosedStore.get(channelId) ?? null;
  },
};

// ============================================================================
// Keyset Cache
// ============================================================================

const keysetCacheStore = new Map<string, KeysetCacheEntry>();

function keysetKey(mint: string, keysetId: string): string {
  return `${mint}|${keysetId}`;
}

export const keysetCache = {
  get(mint: string, keysetId: string): KeysetCacheEntry | null {
    return keysetCacheStore.get(keysetKey(mint, keysetId)) ?? null;
  },

  set(mint: string, keysetId: string, entry: KeysetCacheEntry): void {
    keysetCacheStore.set(keysetKey(mint, keysetId), entry);
    console.log(`  [Store] Cached keyset: ${keysetId} (active=${entry.active})`);
  },

  has(mint: string, keysetId: string): boolean {
    return keysetCacheStore.has(keysetKey(mint, keysetId));
  },

  getActiveIds(mint: string, unit: string): string[] {
    const result: string[] = [];
    for (const [key, entry] of keysetCacheStore) {
      if (key.startsWith(mint + "|") && entry.unit === unit && entry.active) {
        result.push(key.split("|")[1]);
      }
    }
    return result;
  },

  clearForMint(mint: string): void {
    const prefix = mint + "|";
    for (const key of keysetCacheStore.keys()) {
      if (key.startsWith(prefix)) {
        keysetCacheStore.delete(key);
      }
    }
    console.log(`  [Store] Cleared cached keysets for mint: ${mint}`);
  },
};

// ============================================================================
// Channel Status (for status endpoint)
// ============================================================================

export interface ChannelStatus {
  channel_id: string;
  capacity: number;
  balance: number;
  chars_served: number;
  amount_due: number;
  closed: boolean;
  closed_amount?: number;
}

export function getChannelStatus(
  channelId: string,
  pricing: Record<string, { per_char: number; minCapacity: number }>
): ChannelStatus {
  const funding = channelFunding.get(channelId);
  if (!funding) {
    throw new Error("unknown channel");
  }

  const params = JSON.parse(funding.paramsJson);
  const balance = channelBalance.get(channelId);
  const usage = channelUsage.get(channelId);
  const closedData = channelClosed.get(channelId);

  const charsServed = usage?.charsServed ?? 0;
  const unitPricing = pricing[params.unit];
  const pricePerChar = unitPricing?.per_char ?? 0;
  const amountDue = charsServed * pricePerChar;

  return {
    channel_id: channelId,
    capacity: params.capacity,
    balance: balance?.balance ?? 0,
    chars_served: charsServed,
    amount_due: amountDue,
    closed: closedData !== null,
    ...(closedData && { closed_amount: closedData.closedAmount }),
  };
}
