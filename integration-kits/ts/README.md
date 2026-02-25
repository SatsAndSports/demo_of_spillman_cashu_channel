# Spilman TypeScript Integration Kit

Drop-in channel management router and in-memory host for Express.

## Quick start

```bash
npm install
npm run server
```

Environment variables:

- `MINT_URL` (default `http://localhost:3338`)
- `PORT` (default `5002`)
- `SERVER_SECRET_KEY` (hex-encoded 32-byte secret key)

The server mounts management routes under `/channel` and a demo `/ascii` endpoint.

## Using the management router

```ts
import express from "express";
import { WasmSpilmanBridge } from "../wasm/cdk_wasm.js";
import { createInMemoryStores, getActivePricing } from "./stores.js";
import { createSpilmanHost, getServerPubkey } from "./host.js";
import { createSpilmanManagementRouter } from "./router.js";

const stores = createInMemoryStores();
const pricing = { sat: { per_char: 1, minCapacity: 10 } };
const host = createSpilmanHost({
  secretKeyHex: "...",
  mintUrl: "http://localhost:3338",
  pricing,
  stores,
});

const bridge = new WasmSpilmanBridge(host);
const app = express();
app.use(express.json());

app.use(
  "/channel",
  createSpilmanManagementRouter({
    bridge,
    receiverPubkey: getServerPubkey("..."),
    pricing,
    stores,
    getActivePricing: () => getActivePricing(pricing, stores.keysetCache),
  })
);

// Ensure JSON parsing middleware is installed before the router.
```

## WASM artifacts

This kit expects the Node.js WASM artifacts under `wasm/`. In the monorepo they
are automatically synchronized from `web/wasm-nodejs` when running `make build-wasm`.

When splitting into a standalone repo, keep `cdk_wasm.js` and `cdk_wasm_bg.wasm`
together in that directory.
