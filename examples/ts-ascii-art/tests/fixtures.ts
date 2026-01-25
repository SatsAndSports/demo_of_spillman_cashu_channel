import { test as base } from 'vitest';
import { readFileSync } from 'fs';
import * as path from 'path';

const PORT_FILE = path.join(process.cwd(), 'tests', '.test-port');

// Types
interface ChannelParams {
  receiver_pubkey: string;
  pricing: {
    sat: {
      per_char: number;
      minCapacity: number;
    };
  };
  mint: string;
  min_expiry_in_seconds: number;
}

interface Server {
  baseUrl: string;
  mintUrl: string;
  channelParams: ChannelParams;
  pricePerChar: number;
  getAmountDue(charsServed: number): number;
  getMinCapacity(): number;
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

      const pricePerChar = channelParams.pricing.sat.per_char;

      const server: Server = {
        baseUrl,
        mintUrl,
        channelParams,
        pricePerChar,
        getAmountDue(charsServed: number): number {
          return charsServed * pricePerChar;
        },
        getMinCapacity(): number {
          return channelParams.pricing.sat.minCapacity;
        },
      };

      await use(server);
    },
    { scope: 'file' }
  ],
});

// Re-export everything from vitest so tests only need one import
export { describe, expect } from 'vitest';
