import { spawn, ChildProcess } from 'child_process';
import { writeFileSync, rmSync } from 'fs';
import * as net from 'net';
import * as path from 'path';

const MINT_URL = process.env.MINT_URL || 'http://localhost:3338';
const PORT_FILE = path.join(process.cwd(), 'tests', '.test-port');

let serverProcess: ChildProcess | null = null;

/**
 * Find an empty port by binding to port 0 and reading the assigned port.
 */
async function findEmptyPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, () => {
      const address = server.address() as net.AddressInfo;
      const port = address.port;
      server.close(() => resolve(port));
    });
  });
}

/**
 * Check that the mint is available before starting tests.
 */
async function checkMintAvailable(): Promise<void> {
  const errorMessage = `
===========================================
ERROR: Mint not available at ${MINT_URL}

The ts-ascii-art tests require a Cashu mint.

Recommended: Use the Makefile targets that start an ephemeral mint:
  make test-ts-ascii-cdk      # Uses CDK mint
  make test-ts-ascii-nutmix   # Uses NutMix mint

Or set MINT_URL to an existing mint:
  MINT_URL=http://localhost:3338 npm test

See AGENTS.md for more details.
===========================================
`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`${MINT_URL}/v1/keysets`, { signal: controller.signal });
    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`Mint returned HTTP ${response.status}`);
    }

    const data = await response.json() as {
      keysets?: Array<{
        id: string;
        unit: string;
        active: boolean;
        input_fee_ppk?: number;
      }>;
    };

    // Count active keysets
    const activeKeysets = data.keysets?.filter(ks => ks.active) || [];
    console.log(`Mint available at ${MINT_URL} (${activeKeysets.length} active keysets)`);

    // Print keyset details
    if (data.keysets && data.keysets.length > 0) {
      console.log('Keysets:');
      for (const ks of data.keysets) {
        const fee = ks.input_fee_ppk ?? 0;
        const status = ks.active ? 'active' : 'inactive';
        console.log(`  ${ks.id} | ${ks.unit.padEnd(4)} | ${status.padEnd(8)} | fee=${fee} ppk`);
      }
    }
  } catch (e) {
    console.error(errorMessage);
    throw new Error(`Mint not available at ${MINT_URL}`);
  }
}

/**
 * Wait for the server to respond to HTTP requests.
 */
async function waitForServer(port: number, timeoutMs: number = 10000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(`http://localhost:${port}/channel/params`);
      if (response.status !== undefined) {
        // Give it a moment to fully initialize
        await new Promise(resolve => setTimeout(resolve, 200));
        return;
      }
    } catch {
      // Server not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Server did not start within ${timeoutMs}ms`);
}

export async function setup() {
  // Check mint is available before starting tests
  await checkMintAvailable();

  // Find an empty port
  const port = await findEmptyPort();
  console.log(`Found empty port: ${port}`);

  // Start the server
  console.log(`Starting ts-ascii-art server on port ${port}...`);

  serverProcess = spawn('node', ['--import', 'tsx', 'src/index.ts', 'server'], {
    env: {
      ...process.env,
      PORT: String(port),
      MINT_URL: MINT_URL,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: process.cwd(),
  });

  // Log server output for debugging
  serverProcess.stdout?.on('data', (data) => {
    console.log(`[server] ${data.toString().trim()}`);
  });
  serverProcess.stderr?.on('data', (data) => {
    console.error(`[server:err] ${data.toString().trim()}`);
  });

  serverProcess.on('error', (err) => {
    console.error('Failed to start server:', err);
  });

  // Wait for server to be ready
  await waitForServer(port);
  console.log('Server is ready!');

  // Write port to file for fixtures to read (cross-process communication)
  writeFileSync(PORT_FILE, JSON.stringify({ port, mintUrl: MINT_URL }));

  // Store process for teardown
  (globalThis as any).__TEST_SERVER_PROCESS__ = serverProcess;
}

export async function teardown() {
  const proc = (globalThis as any).__TEST_SERVER_PROCESS__ as ChildProcess | null;
  if (proc) {
    console.log('Stopping ts-ascii-art server...');
    proc.kill('SIGTERM');

    // Wait for process to exit
    await new Promise<void>((resolve) => {
      proc.on('exit', () => resolve());
      setTimeout(() => {
        proc.kill('SIGKILL');
        resolve();
      }, 5000);
    });
  }

  // Clean up port file
  rmSync(PORT_FILE, { force: true });
}
