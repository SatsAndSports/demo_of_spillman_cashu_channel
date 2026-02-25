import os
import secrets
import json
import pyfiglet
from typing import Optional
from flask import Flask, request, jsonify
from cdk_spilman_kit import SpilmanStores, BaseSpilmanHost, refresh_keyset_cache
from cdk_spilman_kit.ext.flask import Spilman

# Configuration
SECRET_KEY = os.environ.get("SERVER_SECRET_KEY") or secrets.token_hex(32)
MINT_URL = os.environ.get("MINT_URL", "http://localhost:3338")
PORT = int(os.environ.get("PORT", "5000"))

# Pricing per character
PRICING = {
    "sat":  {"per_char": 1,    "minCapacity": 10},
    "msat": {"per_char": 1000, "minCapacity": 10000},
    "usd":  {"per_char": 1,    "minCapacity": 10, "maxAmountPerOutput": 64},
}

class AsciiArtHost(BaseSpilmanHost):
    def get_amount_due(self, channel_id: str, context_json: Optional[str] = None) -> int:
        # Custom logic for ASCII art: price per character
        usage = self.stores.channel_usage.get(channel_id, {"chars_served": 0})
        total_chars = usage["chars_served"]

        if context_json:
            ctx = json.loads(context_json)
            total_chars += ctx.get("message_length", 0)

        funding = self.stores.channel_funding.get(channel_id)
        unit = "sat"
        if funding:
            params = json.loads(funding["params"])
            unit = params.get("unit", "sat")
        
        per_char = self.pricing.get(unit, self.pricing["sat"])["per_char"]
        return total_chars * per_char

    def record_payment(self, channel_id: str, balance: int, signature: str, context_json: str):
        # Update usage tracking
        super().record_payment(channel_id, balance, signature, context_json)
        ctx = json.loads(context_json)
        if channel_id not in self.stores.channel_usage:
            self.stores.channel_usage[channel_id] = {"chars_served": 0}
        self.stores.channel_usage[channel_id]["chars_served"] += ctx.get("message_length", 0)

app = Flask(__name__)
stores = SpilmanStores()
host = AsciiArtHost(SECRET_KEY, MINT_URL, PRICING, stores)
spilman = Spilman(app, host)

def get_ascii_context():
    data = request.get_json() or {}
    return json.dumps({"message_length": len(data.get("message", ""))})

def validate_ascii_request():
    data = request.get_json() or {}
    if not data.get("message"):
        return jsonify({"error": "Missing 'message'"}), 400
    return None

@app.route("/ascii", methods=["POST"])
@spilman.payment_required(context_provider=get_ascii_context, precheck=validate_ascii_request)
def generate_ascii():
    data = request.get_json() or {}
    message = data.get("message", "")
    
    # decorator injected spilman_payment after validation
    payment = request.spilman_payment
    
    art = pyfiglet.figlet_format(message)
    
    return jsonify({
        "art": art,
        "message": message,
        "payment": {
            "channel_id": payment.channel_id,
            "balance": payment.balance,
            "amount_due": payment.amount_due,
            "capacity": payment.capacity,
        }
    })

if __name__ == "__main__":
    refresh_keyset_cache(stores, MINT_URL, list(PRICING.keys()))
    print(f"Server pubkey: {host.pubkey}")
    app.run(host="0.0.0.0", port=PORT)
