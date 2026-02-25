import base64
import json
from typing import Optional, Any, Callable
from fastapi import APIRouter, Request, HTTPException, Depends, Header, Response
from cdk_spilman import SpilmanBridge
from ..host import BaseSpilmanHost
from ..stores import SpilmanStores

def map_error_status(error_msg: str) -> int:
    lower_msg = error_msg.lower()
    if "channel closed" in lower_msg:
        return 410
    if "channel closing" in lower_msg:
        return 409

    is_bad_request = any(
        x in lower_msg
        for x in [
            "invalid base64",
            "invalid utf8",
            "invalid json",
            "missing field",
            "missing signature",
            "missing channel_id",
        ]
    )

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
    def __init__(self, host: BaseSpilmanHost):
        self.host = host
        self.bridge = SpilmanBridge(self.host)
        self.router = self._create_router()

    def _create_router(self) -> APIRouter:
        router = APIRouter(prefix="/channel")

        @router.get("/params")
        async def get_params():
            return {
                "receiver_pubkey": self.host.pubkey,
                "pricing": self.host.stores.get_active_pricing(self.host.pricing),
                "mints_units_keysets": self.host.stores.get_mints_units_keysets(),
                "min_expiry_in_seconds": 3600,
            }

        @router.post("/register")
        async def register_channel(data: dict):
            if data.get("balance") != 0:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "Bad request",
                        "reason": f"funding requires balance=0, got {data.get('balance')}",
                    },
                )
            
            try:
                result = self.bridge.fund_channel(json.dumps(data))
                return {
                    "success": True,
                    "channel_id": result.channel_id,
                    "capacity": result.capacity,
                    "already_known": result.already_known,
                }
            except Exception as e:
                msg = str(e)
                status = map_error_status(msg)
                raise HTTPException(
                    status_code=status,
                    detail={
                        "success": False,
                        "error": map_error_name(msg),
                        "reason": msg,
                        "status": status,
                    },
                )

        @router.get("/{channel_id}/status")
        async def channel_status(channel_id: str):
            funding = self.host.stores.channel_funding.get(channel_id)
            if not funding:
                raise HTTPException(status_code=404, detail="unknown channel")
            
            params = json.loads(funding["params"])
            payment = self.host.stores.channel_largest_payment.get(channel_id, {})
            closed_info = self.host.stores.channel_closed.get(channel_id)
            
            return {
                "channel_id": channel_id,
                "capacity": params.get("capacity", 0),
                "balance": payment.get("balance", 0),
                "amount_due": self.host.get_amount_due(channel_id, None),
                "closed": closed_info is not None,
                "closed_amount": closed_info.balance if closed_info else None,
            }

        @router.post("/{channel_id}/close")
        async def cooperative_close(channel_id: str, data: dict):
            balance = data.get("balance")
            if balance is None:
                raise HTTPException(status_code=400, detail={"error": "missing balance"})

            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                if closed_info.balance == balance:
                    return {
                        "success": True,
                        "channel_id": channel_id,
                        "already_closed": True,
                        "total_value": closed_info.receiver_sum + closed_info.sender_sum,
                        "receiver_sum": closed_info.receiver_sum,
                        "sender_sum": closed_info.sender_sum,
                        "sender_proofs": closed_info.sender_proofs,
                    }
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "channel already closed at different balance",
                        "closed_amount": closed_info.balance,
                        "requested_amount": balance,
                    },
                )

            data["channel_id"] = channel_id
            try:
                result = self.bridge.execute_cooperative_close(json.dumps(data))
                return {
                    "success": True,
                    "channel_id": result.channel_id,
                    "total_value": result.total_value,
                    "receiver_sum": result.receiver_sum,
                    "sender_sum": result.sender_sum,
                    "sender_proofs": json.loads(result.sender_proofs),
                    "already_closed": result.already_closed,
                }
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    raise HTTPException(status_code=err_data.get("status", 500), detail=err_data)
                except:
                    raise HTTPException(status_code=500, detail=msg)

        @router.post("/{channel_id}/unilateral-close")
        async def unilateral_close(channel_id: str):
            closed_info = self.host.stores.channel_closed.get(channel_id)
            if closed_info:
                return {
                    "success": True,
                    "channel_id": channel_id,
                    "already_closed": True,
                    "earnedBeforeStage2Fees": closed_info.receiver_sum,
                }

            try:
                result = self.bridge.execute_unilateral_close(channel_id)
                return {
                    "success": True,
                    "channel_id": channel_id,
                    "earnedBeforeStage2Fees": result.receiver_sum,
                    "already_closed": False,
                }
            except Exception as e:
                msg = str(e)
                try:
                    err_data = json.loads(msg)
                    raise HTTPException(status_code=err_data.get("status", 500), detail=err_data)
                except:
                    raise HTTPException(status_code=500, detail=msg)

        return router

    def payment_dependency(self, context_provider: Optional[Callable[[Request], str]] = None, precheck: Optional[Callable[[Request], Any]] = None):
        async def dependency(request: Request, x_cashu_channel: Optional[str] = Header(None)):
            return await self._process_payment(request, x_cashu_channel, context_provider, precheck)

        return dependency

    async def payment_required(self, request: Request, x_cashu_channel: Optional[str] = Header(None)):
        return await self._process_payment(request, x_cashu_channel)

    async def _process_payment(
        self,
        request: Request,
        x_cashu_channel: Optional[str],
        context_provider: Optional[Callable[[Request], str]] = None,
        precheck: Optional[Callable[[Request], Any]] = None,
    ):
        if precheck:
            precheck_result = precheck(request)
            if precheck_result is not None:
                if isinstance(precheck_result, HTTPException):
                    raise precheck_result
                if isinstance(precheck_result, tuple) and len(precheck_result) == 2:
                    status_code, detail = precheck_result
                else:
                    status_code, detail = 400, precheck_result
                raise HTTPException(status_code=status_code, detail=detail)

        if not x_cashu_channel:
            raise HTTPException(status_code=402, detail={
                "error": "Payment required",
                "reason": "Missing X-Cashu-Channel header",
            })

        try:
            payment_json = base64.b64decode(x_cashu_channel).decode()
        except:
            raise HTTPException(status_code=400, detail={
                "error": "Invalid payment header",
                "reason": "invalid base64",
            })

        if context_provider:
            try:
                context = context_provider(request)
            except Exception as e:
                print(f"  [Spilman] Context provider failed: {e}")
                context = "{}"
        else:
            context = getattr(request.state, "spilman_context", "{}")

        try:
            result = self.bridge.process_payment(payment_json, context)
            request.state.spilman_payment = result
            return result
        except Exception as e:
            msg = str(e)
            raise HTTPException(
                status_code=map_error_status(msg),
                detail={
                    "success": False,
                    "error": "Payment failed",
                    "reason": msg,
                },
                headers={"X-Cashu-Channel": json.dumps({"error": msg})},
            )

def add_payment_confirmation_header(response: Response, payment_result: Any):
    if payment_result:
        payment_info = {
            "channel_id": payment_result.channel_id,
            "balance": payment_result.balance,
            "amount_due": payment_result.amount_due,
            "capacity": payment_result.capacity,
        }
        response.headers["X-Cashu-Channel"] = json.dumps(payment_info)
