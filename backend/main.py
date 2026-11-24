"""PS2 evidence API. No raw notification ingestion, URL visiting or persistence."""
import asyncio
import hmac
import ipaddress
import os
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from evidence import domain_evidence, bounded_json

app = FastAPI(title="PS2 evidence verification", docs_url=None, redoc_url=None)

class Query(BaseModel):
    kind: Literal["url", "claim"]
    query: str = Field(min_length=1, max_length=2000)


def public_url(value: str) -> str:
    try:
        u = urlsplit(value)
        host = u.hostname or ""
        if u.scheme not in ("http", "https") or not host or u.username or u.password:
            raise ValueError()
        if u.port not in (None, 80, 443) or "." not in host or host.endswith((".local", ".internal")):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError()
        if address is None and (host.replace(".", "").isdigit() or ":" in host):
            raise ValueError()
        return urlunsplit((u.scheme, host.encode("idna").decode(), u.path or "/", "", ""))
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Provide a public HTTP(S) URL without credentials")


@app.get("/health")
def health():
    return {"status": "ok", "model": "on-device advisory model; server does not classify messages", "raw_notification_storage": False}


@app.post("/verify")
async def verify(body: Query, authorization: str = Header(default="")):
    secret = os.getenv("PS2_API_TOKEN", "")
    if not secret or not hmac.compare_digest(authorization, f"Bearer {secret}"):
        raise HTTPException(401, "Valid backend token required")
    try:
        async with asyncio.timeout(9):
            async with httpx.AsyncClient(timeout=7, follow_redirects=False, trust_env=False) as client:
                if body.kind == "url":
                    url = public_url(body.query)
                    registry = await domain_evidence(client, url)
                    key = os.getenv("WEB_RISK_API_KEY")
                    if not key:
                        return {"verdict": "Unverified", "reason": "URL reputation provider not configured. Registry information alone cannot establish safety.", "domain_evidence": registry}
                    record = await bounded_json(client, "https://webrisk.googleapis.com/v1/uris:search", params={
                        "uri": url, "key": key, "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]})
                    threats = record.get("threat", {}).get("threatTypes", [])
                    return {"verdict": "High Risk" if threats else "Unverified", "evidence": threats,
                            "source": "Google Web Risk", "domain_evidence": registry, "reason": "No listing does not prove safety" if not threats else "Threat listing found"}
                key = os.getenv("FACT_CHECK_API_KEY")
                if not key:
                    return {"verdict": "Unverified", "reason": "Fact Check provider not configured"}
                record = await bounded_json(client, "https://factchecktools.googleapis.com/v1alpha1/claims:search", params={"query": body.query, "key": key, "pageSize": 5})
                evidence = [{"claim": c.get("text", "")[:1000], "reviews": [
                    {"publisher": v.get("publisher", {}).get("name"), "url": v.get("url"),
                     "rating": v.get("textualRating"), "date": v.get("reviewDate")}
                    for v in c.get("claimReview", [])[:3]]} for c in record.get("claims", [])[:5]]
                return {"verdict": "Unverified", "evidence": evidence,
                        "reason": "Retrieved candidates require matching claim, date and context. Retrieval alone does not settle the claim."}
    except (httpx.HTTPError, TimeoutError, ValueError):
        return {"verdict": "Unverified", "reason": "Evidence provider unavailable or invalid response"}
