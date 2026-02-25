import base64
import json
from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from cdk_spilman import SpilmanBridge
from ..host import BaseSpilmanHost
from ..stores import SpilmanStores

def map_error_status(error_msg: str) -> int:
    lower_msg = error_msg.lower()
    if "channel closed" in lower_msg: return 410
    if "channel closing" in lower_msg: return 409
    
    # Standard 400 Bad Request cases (parsing/malformed request)
    is_bad_request = any(x in lower_msg for x in ["invalid base64", "invalid utf8", "invalid json", "missing field", "missing signature", "missing channel_id"])
    
    # Bridge often uses "expected ..." for type errors
    if not is_bad_request:
        if "expected" in lower_msg and any(x in lower_msg for x in ["string", "integer", "u64"]):
            is_bad_request = True
            
    if is_bad_request:
        return 400
        
    if "internal" in lower_msg or "misconfigured" in lower_msg:
        return 500
    return 402

def map_error_name(error_msg: str) -> str:
    if map_error_status(error_msg) == 400:
        return "Bad request"
    return "Registration failed"

class Spilman:
    def __init__(self, app=None, host: BaseSpilmanHost = None):
        self.host = host
        self.bridge = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app, host: BaseSpilmanHost = None):
        if host:
            self.host = host
        
        if not self.host:
            raise RuntimeError("Spilman host must be provided either in constructor or init_app")
            
        self.bridge = SpilmanBridge(self.host)
        
        # Register management blueprint
        bp = Blueprint("spilman_management", __name__, url_prefix="/channel")
        
        @bp.route("/params")
        def get_params():
            return jsonify({
                "receiver_pubkey": self.host.pubkey,
                "pricing": self.host.stores.get_active_pricing(self.host.pricing),
                "mints_units_keysets": self.host.stores.get_mints_units_keysets(),
                "min_expiry_in_seconds": 3600,
            })

        @bp.route("/register", methods=["POST"])
        def register_channel():
            data = request.get_json() or {}
            if data.get("balance") != 0:
                return jsonify({
                    "error": "Bad request",
                    "reason": f"funding requires balance=0, got {data.get('balance')}"
                }), 400
            
            try:
                result = self.bridge.fund_channel(json.dumps(data))
                return jsonify({
                    "success": True,
                    "channel_id": result.channel_id,
                    "capacity": result.capacity,
                    "already_known": result.already_known,
                })
            except Exception as e:
                msg = str(e)
                return jsonify({
                    "success": False,
                    "error": map_error_name(msg),
                    "reason": msg,
                    "status": map_error_status(msg)
                }), map_error_status(msg)

        @bp.route("/<channel_id>/status")
        def channel_status(channel_id):
            funding = self.host.stores.channel_funding.get(channel_id)
            if not funding:
                return jsonify({"error": "unknown channel"}), 404
            
            params = json.loads(funding["params"])
            payment = self.host.stores.channel_largest_payment.get(channel_id, {})
            closed_info = self.host.stores.channel_closed.get(channel_id)
            
            return jsonify({
                "channel_id": channel_id,
                "capacity": params.get("capacity", 0),
                "balance": payment.get("balance", 0),
                "amount_due": self.host.get_amount_due(channel_id, None),
                "closed": closed_info is not None,
                "closed_amount": closed_info.balance if closed_info else None,
            })

        @bp.route("/<channel_id>/close", methods=["POST"])
        def cooperative_close(channel_id):
            data = request.get_json() or {}
            balance = data.get("balance")
            if balance is None:
                return jsonify({"error": "missing balance"}), 400
            
            # Check if already closed - return idempotent response
            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                if closed_info.balance == balance:
                    return jsonify({
                        "success": True,
                        "channel_id": channel_id,
                        "already_closed": True,
                        "total_value": closed_info.receiver_sum + closed_info.sender_sum,
                        "receiver_sum": closed_info.receiver_sum,
                        "sender_sum": closed_info.sender_sum,
                        "sender_proofs": closed_info.sender_proofs,
                    })
                else:
                    return jsonify({
                        "error": "channel already closed at different balance",
                        "closed_amount": closed_info.balance,
                        "requested_amount": balance,
                    }), 400

            data["channel_id"] = channel_id
            try:
                result = self.bridge.execute_cooperative_close(json.dumps(data))
                return jsonify({
                    "success": True,
                    "channel_id": result.channel_id,
                    "total_value": result.total_value,
                    "receiver_sum": result.receiver_sum,
                    "sender_sum": result.sender_sum,
                    "sender_proofs": json.loads(result.sender_proofs),
                    "already_closed": result.already_closed,
                })
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    return jsonify(err_data), err_data.get("status", 500)
                except:
                    return jsonify({"error": msg}), 500

        @bp.route("/<channel_id>/unilateral-close", methods=["POST"])
        def unilateral_close(channel_id):
            # Check if already closed - return idempotent response
            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                return jsonify({
                    "success": True,
                    "channel_id": channel_id,
                    "already_closed": True,
                    "earnedBeforeStage2Fees": closed_info.receiver_sum,
                })

            try:
                result = self.bridge.execute_unilateral_close(channel_id)
                return jsonify({
                    "success": True,
                    "channel_id": channel_id,
                    "earnedBeforeStage2Fees": result.receiver_sum,
                    "already_closed": False,
                })
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    return jsonify(err_data), err_data.get("status", 500)
                except:
                    return jsonify({"error": msg}), 500

        app.register_blueprint(bp)
        app.extensions["spilman"] = self

    def payment_required(self, f=None, context_provider=None, precheck=None):
        if f is None:
            return lambda func: self.payment_required(func, context_provider, precheck)

        @wraps(f)
        def decorated(*args, **kwargs):
            if precheck:
                precheck_result = precheck()
                if precheck_result is not None:
                    return precheck_result

            header_b64 = request.headers.get("X-Cashu-Channel")
            if not header_b64:
                return jsonify({
                    "error": "Payment required",
                    "reason": "Missing X-Cashu-Channel header"
                }), 402
            
            try:
                payment_json = base64.b64decode(header_b64).decode()
            except:
                return jsonify({
                    "error": "Invalid payment header",
                    "reason": "invalid base64"
                }), 400
            
            context = "{}"
            if context_provider:
                try:
                    context = context_provider()
                except Exception as e:
                    print(f"  [Spilman] Context provider failed: {e}")
            
            try:
                result = self.bridge.process_payment(payment_json, context)
                request.spilman_payment = result
                
                resp = f(*args, **kwargs)
                
                # Handle different return types
                if isinstance(resp, tuple):
                    r_obj, status = resp
                else:
                    r_obj, status = resp, 200
                
                if status == 200:
                    payment_info = {
                        "channel_id": result.channel_id,
                        "balance": result.balance,
                        "amount_due": result.amount_due,
                        "capacity": result.capacity,
                    }
                    # If it's a Response object, add the header
                    if hasattr(r_obj, "headers"):
                        r_obj.headers["X-Cashu-Channel"] = json.dumps(payment_info)
                
                return resp
            except Exception as e:
                msg = str(e)
                response = jsonify({
                    "success": False,
                    "error": "Payment failed",
                    "reason": msg
                })
                response.headers["X-Cashu-Channel"] = json.dumps({"error": msg})
                return response, map_error_status(msg)
        
        return decorated
