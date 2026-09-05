"""
ERC-8004 identity registration routes.

Additive router for the Identity-registration step (see
guardian/passport/erc8004_registrar.py). Inactive unless
GUARDIAN_ERC8004_ENABLED=true; the public file endpoint still serves a
404 (not an error) when the feature is disabled.
"""
import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from backend.main import (
    PUBLIC_BASE_URL,
    _enforce_rate_limit,
    _get_passport_engine,
    _get_user_rate_limit,
    get_current_principal,
    logger,
)
from guardian.passport.erc8004_registrar import (
    RegistrarMisconfigured,
    build_registration_file,
    configured_chains,
    default_db_path,
    enqueue_registration,
)

router = APIRouter()


def _check_agent_access(principal: Dict[str, Any], agent_id: str) -> None:
    """Mirror cortex_routes tenant-scoping: admins global, others own-tenant."""
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    if role == "admin" or (role == "auditor" and user_tenant == "org_guardian"):
        return
    passport = _get_passport_engine().get_passport(agent_id)
    if passport is None or getattr(passport, "tenant_id", "default") != user_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: you do not have access to this agent.",
        )


@router.post("/api/v1/erc8004/register", tags=["ERC-8004 Identity"])
def erc8004_register(
    body: Dict[str, Any] = Body(...),
    principal: Dict[str, Any] = Depends(get_current_principal),
):
    """(Re)queue ERC-8004 registration for an agent. Admin only."""
    username = principal.get("username", "unknown")
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    agent_id = str(body.get("agent_id", "")).strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    chain = str(body.get("chain", "")).strip()

    owner_address = body.get("owner_address") or None
    if owner_address is not None:
        from guardian.passport.erc8004_registrar import is_valid_owner_address
        if not isinstance(owner_address, str) or not is_valid_owner_address(
            owner_address
        ):
            raise HTTPException(
                status_code=400, detail="owner_address must be a 0x-prefixed "
                "20-byte EVM address"
            )

    passport = _get_passport_engine().get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail="Agent has no Guardian passport")

    try:
        if chain:
            ok = _enqueue_single(chain, agent_id, passport.passport_id,
                                 owner_address)
            results = {chain: "queued" if ok else "skipped"}
        else:
            ok = enqueue_registration(
                default_db_path(), agent_id, passport.passport_id,
                owner_address=owner_address,
            )
            results = {"all_configured_chains": "queued" if ok else "skipped"}
    except RegistrarMisconfigured as exc:
        results = {chain or "all": f"misconfigured: {exc}"}
        ok = False
    except Exception as exc:  # noqa: BLE001
        logger.exception("ERC-8004 register route failed")
        results = {chain or "all": f"error: {exc}"}
        ok = False

    if ok:
        return JSONResponse(
            status_code=202,
            content={
                "success": True,
                "agent_id": agent_id,
                "results": results,
                "hint": "worker processes queued rows on its poll interval",
            },
        )
    return JSONResponse(
        status_code=400,
        content={"success": False, "agent_id": agent_id, "results": results},
    )


def _enqueue_single(chain: str, agent_id: str, passport_id: str,
                    owner_address: Optional[str] = None) -> bool:
    from guardian.passport.erc8004_registrar import ERC8004Registrar

    registrar = ERC8004Registrar(chain, default_db_path())
    # Admin route: reset a FAILED row so a re-register actually retries.
    return bool(registrar.enqueue(agent_id, passport_id, reset_failed=True,
                                  owner_address=owner_address))


@router.get("/api/v1/erc8004/status/{agent_id}", tags=["ERC-8004 Identity"])
def erc8004_status(
    agent_id: str,
    principal: Dict[str, Any] = Depends(get_current_principal),
):
    """Registration queue state for an agent (tenant-scoped)."""
    username = principal.get("username", "unknown")
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    _check_agent_access(principal, agent_id)

    from guardian.passport.erc8004_registrar import ERC8004Registrar

    rows = ERC8004Registrar(
        configured_chains()[0] if configured_chains() else "monad-testnet",
        default_db_path(),
    ).get_status(agent_id) if configured_chains() else []
    return {"agent_id": agent_id, "enabled": True, "registrations": rows}


@router.get("/api/v1/erc8004/agents/{agent_id}.json", tags=["ERC-8004 Identity"])
def erc8004_registration_file(agent_id: str):
    """Public ERC-8004 registration file (the URI written into the registry)."""
    from guardian.passport import erc8004_registrar as reg

    if not reg.is_enabled():
        raise HTTPException(status_code=404, detail="Not found")

    passport = _get_passport_engine().get_passport(agent_id)
    if passport is None or not getattr(passport, "is_active", True):
        raise HTTPException(status_code=404, detail="Not found")

    token_id = None
    try:
        from guardian.passport.erc8004_registrar import ERC8004Registrar

        rows = ERC8004Registrar(
            reg.configured_chains()[0] if reg.configured_chains() else "monad-testnet",
            default_db_path(),
        ).get_status(agent_id)
        confirmed = [r for r in rows if r["status"] == "confirmed" and r["token_id"]]
        if confirmed:
            token_id = int(confirmed[0]["token_id"])
    except Exception:  # noqa: BLE001 — file must serve even with queue trouble
        pass

    chain = reg.configured_chains()[0] if reg.configured_chains() else "monad-testnet"
    file_obj = build_registration_file(
        agent_id=agent_id,
        chain=chain,
        token_id=token_id,
        base_url=PUBLIC_BASE_URL,
    )
    return {
        **file_obj,
        "_meta": {
            "generatedAt": time.time(),
            "schemaVersion": 1,
        },
    }
