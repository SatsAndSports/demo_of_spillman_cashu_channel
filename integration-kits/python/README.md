# CDK Spilman Python Integration Kit

Standard components for integrating Spilman payment channels into Python web applications.

## Features

- **Standard Management Routes**: Pre-built endpoints for `/params`, `/register`, `/close`, etc.
- **Flask & FastAPI Support**: Built-in extensions and decorators/dependencies.
- **In-Memory Storage**: Default storage for development (extensible).
- **Automatic Keyset Management**: Handles fetching and refreshing mint keysets.

## Installation

```bash
pip install cdk-spilman-kit[flask]  # or [fastapi]
```

## Usage (Flask)

```python
from flask import Flask, request, jsonify
from cdk_spilman_kit import SpilmanStores, BaseSpilmanHost
from cdk_spilman_kit.ext.flask import Spilman

app = Flask(__name__)
stores = SpilmanStores()
host = BaseSpilmanHost(SECRET_KEY, MINT_URL, PRICING, stores)
spilman = Spilman(app, host)

@app.route("/api/data", methods=["POST"])
@spilman.payment_required
def get_data():
    return jsonify({"data": "Protected content"})

# Optional: pass context or precheck before charging
@spilman.payment_required(
    context_provider=lambda: "{\"message_length\": 5}",
    precheck=lambda: None,
)
def get_data_with_context():
    return jsonify({"data": "Protected content"})
```

## Usage (FastAPI)

```python
from fastapi import FastAPI, Depends
from cdk_spilman_kit import SpilmanStores, BaseSpilmanHost
from cdk_spilman_kit.ext.fastapi import Spilman

app = FastAPI()
stores = SpilmanStores()
host = BaseSpilmanHost(SECRET_KEY, MINT_URL, PRICING, stores)
spilman = Spilman(host)

app.include_router(spilman.router)

@app.post("/api/data")
async def get_data(payment=Depends(spilman.payment_required)):
    return {"data": "Protected content"}

# Optional: pass context or precheck before charging
context_dep = spilman.payment_dependency(
    context_provider=lambda request: "{\"message_length\": 5}",
    precheck=lambda request: None,
)

@app.post("/api/data-with-context")
async def get_data_with_context(payment=Depends(context_dep)):
    return {"data": "Protected content"}
```
