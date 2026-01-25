import { test as base } from 'vitest';
import { readFileSync } from 'fs';
import * as path from 'path';

const PORT_FILE = path.join(process.cwd(), 'tests', '.test-port');

// Types
interface UnitPricing {
  per_char: number;
  minCapacity: number;
}

interface ChannelParams {
  receiver_pubkey: string;
  pricing: Record<string, UnitPricing>;
  mint: string;
  min_expiry_in_seconds: number;
}

interface Server {
  baseUrl: string;
  mintUrl: string;
  channelParams: ChannelParams;
  getPricePerChar(unit: string): number;
  getAmountDue(charsServed: number, unit: string): number;
  getMinCapacity(unit: string): number;
}

export const test = base.extend<{
  server: Server;
}>({
  server: [
    async ({}, use) => {
      // Read port and mint URL from file (written by globalSetup)
      let port: number;
      let mintUrl: string;
      try {
        const data = JSON.parse(readFileSync(PORT_FILE, 'utf-8'));
        port = data.port;
        mintUrl = data.mintUrl;
      } catch (e) {
        throw new Error(`Failed to read test config from ${PORT_FILE} - globalSetup may have failed: ${e}`);
      }

      const baseUrl = `http://localhost:${port}`;

      // Fetch channel params once
      const paramsRes = await fetch(`${baseUrl}/channel/params`);
      const channelParams: ChannelParams = await paramsRes.json();

      const server: Server = {
        baseUrl,
        mintUrl,
        channelParams,
        getPricePerChar(unit: string): number {
          return channelParams.pricing[unit]?.per_char ?? 0;
        },
        getAmountDue(charsServed: number, unit: string): number {
          return charsServed * this.getPricePerChar(unit);
        },
        getMinCapacity(unit: string): number {
          return channelParams.pricing[unit]?.minCapacity ?? 0;
        },
      };

      await use(server);
    },
    { scope: 'file' }
  ],
});

// Re-export everything from vitest so tests only need one import
export { describe, expect } from 'vitest';

// Export types for use in test files
export type { Server, ChannelParams };
