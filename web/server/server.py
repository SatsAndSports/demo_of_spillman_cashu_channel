"""
Cashu-Gated Video Server

A simple Flask server that serves HLS video segments in exchange for
Spilman channel balance updates.

Payment verification includes:
- Channel ID verification (using Rust code via PyO3)
- Balance must increase with each request
- (TODO) Signature verification
"""

import os
import json
import base64
import logging
from flask import Flask, request, send_from_directory, abort, jsonify
from flask_cors import CORS
import secp256k1
import cdk_py

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
CORS(app)

# Load server's private key
KEY_FILE = os.path.join(os.path.dirname(__file__), 'server_key.json')

def load_server_key():
    """Load the server's private key and derive the public key."""
    with open(KEY_FILE, 'r') as f:
        key_data = json.load(f)
    secret_hex = key_data['secret_hex']
    secret_bytes = bytes.fromhex(secret_hex)
    privkey = secp256k1.PrivateKey(secret_bytes)
    pubkey_bytes = privkey.pubkey.serialize()  # compressed, 33 bytes
    return secret_hex, pubkey_bytes.hex()

SERVER_SECRET_HEX, SERVER_PUBKEY_HEX = load_server_key()
log.info(f"Server pubkey: {SERVER_PUBKEY_HEX}")

# Approved mints for channel setup
APPROVED_MINTS = ['http://localhost:3338']

# In-memory channel state: channel_id -> current_balance
channels = {}


def compute_channel_id(params: dict) -> str:
    """
    Compute the channel_id from params JSON using Rust code via PyO3.
    """
    params_json = json.dumps(params)
    return cdk_py.compute_channel_id_from_json(params_json, SERVER_SECRET_HEX)

# Price per segment in sats
PRICE_PER_SEGMENT = 1

# Media directory (relative to server.py or absolute)
MEDIA_DIR = os.environ.get('MEDIA_DIR', '../media')


def parse_payment(header_value):
    """Parse the X-Cashu-Payment header (base64-encoded JSON)."""
    try:
        decoded = base64.b64decode(header_value)
        payment = json.loads(decoded)
        log.debug(f"Parsed payment: {payment}")
        return payment
    except Exception as e:
        log.warning(f"Failed to parse payment header: {e}")
        return None


def verify_payment(payment):
    """
    Verify that the payment is valid.

    Checks:
    - channel_id and balance are present
    - balance has increased since last request
    - On first payment, logs computed vs claimed channel_id for inspection

    Returns (success, error_message)
    """
    if not payment:
        return False, "Invalid payment format"

    channel_id = payment.get('channel_id')
    new_balance = payment.get('balance')
    params = payment.get('params')

    if not channel_id or new_balance is None:
        return False, "Missing channel_id or balance"

    # On first payment from this channel, verify channel_id
    if channel_id not in channels:
        if not params:
            return False, "First payment must include params for channel verification"

        try:
            computed_id = compute_channel_id(params)
            log.info(f"New channel - claimed:  {channel_id}")
            log.info(f"New channel - from Rust: {computed_id}")
            if channel_id != computed_id:
                log.warning("Channel IDs DO NOT match - rejecting!")
                return False, "Channel ID verification failed"
            log.info("Channel IDs match!")
        except Exception as e:
            log.warning(f"Could not compute channel_id via Rust: {e}")
            return False, f"Channel verification error: {e}"

    current_balance = channels.get(channel_id, 0)

    if new_balance <= current_balance:
        log.warning(f"Payment rejected: channel={channel_id[:16]}... current={current_balance} received={new_balance}")
        return False, f"Balance must increase (current: {current_balance}, received: {new_balance})"

    # Update stored balance
    channels[channel_id] = new_balance
    log.info(f"Payment accepted: channel={channel_id[:16]}... balance={current_balance} -> {new_balance}")

    return True, None


@app.route('/')
def index():
    """Serve the client app."""
    log.info("Serving index.html")
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files (JS, CSS, etc.)."""
    log.debug(f"Serving static file: {filename}")
    return send_from_directory('static', filename)


@app.route('/wasm/<path:filename>')
def serve_wasm(filename):
    """Serve WASM files."""
    log.debug(f"Serving WASM file: {filename}")
    wasm_dir = os.path.join(os.path.dirname(__file__), '..', 'wasm')
    return send_from_directory(wasm_dir, filename)


@app.route('/channel/params')
def channel_params():
    """Return parameters the server (receiver) approves for channel setup."""
    log.info("Channel params requested")
    return jsonify({
        'receiver_pubkey': SERVER_PUBKEY_HEX,
        'approved_mints': APPROVED_MINTS,
        'price_per_segment': PRICE_PER_SEGMENT
    })


@app.route('/videos')
def list_videos():
    """List available videos (no payment required)."""
    videos = []
    media_path = os.path.abspath(MEDIA_DIR)

    if os.path.exists(media_path):
        for name in os.listdir(media_path):
            video_dir = os.path.join(media_path, name)
            if os.path.isdir(video_dir) and os.path.exists(os.path.join(video_dir, 'master.m3u8')):
                videos.append({
                    'name': name,
                    'manifest': f'/media/{name}/master.m3u8'
                })

    log.info(f"Listed {len(videos)} videos")
    return jsonify({'videos': videos, 'price_per_segment': PRICE_PER_SEGMENT})


@app.route('/media/<path:filepath>')
def serve_media(filepath):
    """
    Serve media files (manifests and segments).
    Requires payment header.
    """
    log.info(f"Media request: {filepath}")

    payment_header = request.headers.get('X-Cashu-Payment')

    if not payment_header:
        log.warning(f"No payment header for: {filepath}")
        abort(402, description="Payment Required - include X-Cashu-Payment header")

    payment = parse_payment(payment_header)
    valid, error = verify_payment(payment)

    if not valid:
        log.warning(f"Payment invalid for {filepath}: {error}")
        abort(402, description=f"Payment Invalid: {error}")

    # Serve the file
    media_path = os.path.abspath(MEDIA_DIR)
    full_path = os.path.join(media_path, filepath)

    if not os.path.exists(full_path):
        log.warning(f"File not found: {full_path}")
        abort(404, description="File not found")

    directory = os.path.dirname(full_path)
    filename = os.path.basename(full_path)

    # Set correct content type for HLS
    mimetype = None
    if filepath.endswith('.m3u8'):
        mimetype = 'application/vnd.apple.mpegurl'
    elif filepath.endswith('.ts'):
        mimetype = 'video/mp2t'

    log.info(f"Serving: {filepath}")
    return send_from_directory(directory, filename, mimetype=mimetype)


@app.route('/channel/status/<channel_id>')
def channel_status(channel_id):
    """Get current channel status (for debugging)."""
    balance = channels.get(channel_id, 0)
    log.info(f"Channel status: {channel_id} = {balance}")
    return jsonify({
        'channel_id': channel_id,
        'balance': balance
    })


@app.route('/channel/reset/<channel_id>', methods=['POST'])
def channel_reset(channel_id):
    """Reset a channel (for testing)."""
    old_balance = channels.get(channel_id, 0)
    if channel_id in channels:
        del channels[channel_id]
    log.info(f"Channel reset: {channel_id} (was {old_balance})")
    return jsonify({'status': 'reset', 'channel_id': channel_id})


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Cashu-Gated Video Server')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--media', default='../media', help='Path to media directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger(__name__).setLevel(logging.DEBUG)

    MEDIA_DIR = args.media

    log.info(f"Starting server on {args.host}:{args.port}")
    log.info(f"Media directory: {os.path.abspath(MEDIA_DIR)}")
    log.info(f"Price per segment: {PRICE_PER_SEGMENT} sat")

    app.run(host=args.host, port=args.port, debug=args.debug)
