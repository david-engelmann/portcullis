#!/usr/bin/env python3
"""Standalone standard-library System One judge helper for portcullis under PC-35.

Reads a canonical PC-26 referral request from standard input, formats it for the
selected System One provider, posts it over HTTPS, and writes a canonical PC-26
reply JSON document to standard output. Uses zero third-party dependencies.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MODEL = "jev-1.14.0"
VERDICT_LABELS = ("allow", "deny", "escalate", "other")
MAX_REPLY_BYTES = 1_048_576

ENDPOINTS = {
    "typesafe": "https://api.typesafe.ai/v1/systemone",
    "google": "https://generativelanguage.googleapis.com/v1beta/decisions",
    "openai": "https://api.openai.com/v1/decisions",
    "perplexity": "https://api.perplexity.ai/v1/decisions",
}

ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
ROUTE_SEG_RE = re.compile(r"^[A-Za-z0-9._@-]+$")


class EnvelopeFailureError(ValueError):
    """Raised when an upstream provider envelope explicitly reports failure."""


class MalformedReplyError(ValueError):
    """Raised when a completed provider response is syntactically invalid JSON."""


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, val in pairs:
        if key in out:
            raise MalformedReplyError(f"duplicate JSON key {key}")
        out[key] = val
    return out


def _reject_nonfinite(token: str) -> object:
    raise MalformedReplyError(f"non-finite JSON constant {token}")


def strict_loads(text: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise MalformedReplyError(str(exc)) from exc


def canonical_dumps(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, allow_nan=False)


def is_valid_model_name(name: object) -> bool:
    if not isinstance(name, str) or not (1 <= len(name) <= 128):
        return False
    return all(0x21 <= ord(ch) <= 0x7E for ch in name)


def detect_provider(model: str) -> str:
    if model.startswith("typesafe/") or model.startswith("jev-"):
        return "typesafe"
    if (
        model.startswith("google/")
        or model.startswith("models/gemini-decision-")
        or model.startswith("gemini-decision-")
    ):
        return "google"
    if (
        model.startswith("openai/")
        or model.startswith("gpt-6-")
        or model.startswith("gpt-oss-safeguard")
    ):
        return "openai"
    if model.startswith("perplexity/") or model.startswith("pplx-decider"):
        return "perplexity"
    if (
        model.startswith("cloudflare/")
        or model.startswith("@cf/cloudflare/clef")
        or model.startswith("clef")
    ):
        return "cloudflare"
    return "typesafe"


def wire_model_name(provider: str, model: str) -> str:
    if provider == "typesafe":
        return model.removeprefix("typesafe/")
    if provider == "google":
        stripped = model.removeprefix("google/")
        return stripped.removeprefix("models/")
    if provider == "openai":
        return model.removeprefix("openai/")
    if provider == "perplexity":
        return model.removeprefix("perplexity/")
    if provider == "cloudflare":
        stripped = model.removeprefix("cloudflare/")
        if stripped == "@cf/cloudflare/clef":
            return "clef"
        if stripped == "@cf/cloudflare/clef-flash":
            return "clef-flash"
        if stripped == "@cf/cloudflare/clef-omni":
            return "clef-omni"
        return stripped
    raise ValueError(f"unknown provider {provider}")


def cloudflare_route_model(model: str) -> str:
    stripped = model.removeprefix("cloudflare/")
    if stripped == "clef":
        return "@cf/cloudflare/clef"
    if stripped == "clef-flash":
        return "@cf/cloudflare/clef-flash"
    if stripped == "clef-omni":
        return "@cf/cloudflare/clef-omni"
    return stripped


def validate_https_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("endpoint URL must use https with an explicit host and no userinfo")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint URL carries an invalid port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("endpoint URL port stands outside 1 through 65535")
    if any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in url):
        raise ValueError("endpoint URL contains whitespace or control characters")
    return url


def cloudflare_endpoint(account_id: str, model: str) -> str:
    if not ACCOUNT_ID_RE.match(account_id):
        raise ValueError("invalid Cloudflare account identifier")
    if not is_valid_model_name(model):
        raise ValueError("invalid Cloudflare model identifier")
    route = cloudflare_route_model(model)
    if not route or route.startswith("/") or route.endswith("/"):
        raise ValueError("invalid Cloudflare model route")
    for seg in route.split("/"):
        if not seg or seg in (".", "..") or not ROUTE_SEG_RE.match(seg):
            raise ValueError("disallowed Cloudflare route segment")
    return f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{route}"


def resolve_endpoint(provider: str, model: str, explicit_url: str | None) -> str:
    override = explicit_url or os.environ.get("DECISION_API_URL")
    if override:
        return validate_https_url(override)
    if provider == "cloudflare":
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        if not account_id:
            raise ValueError("CLOUDFLARE_ACCOUNT_ID is required for the Cloudflare provider")
        return cloudflare_endpoint(account_id, model)
    return ENDPOINTS[provider]


def format_provider_request(doc: dict[str, object], provider: str, model: str) -> dict[str, object]:
    if not is_valid_model_name(model):
        raise ValueError("invalid model identifier")
    state = doc.get("state")
    questions = doc.get("questions")
    if not isinstance(state, str) or not isinstance(questions, dict):
        raise ValueError("referral request must carry state string and questions object")
    verdict = questions.get("verdict")
    risk = questions.get("risk")
    if not isinstance(verdict, dict) or not isinstance(risk, dict):
        raise ValueError("referral questions must carry verdict and risk objects")
    criteria = verdict.get("criteria")
    v_inst = verdict.get("instructions")
    r_levels = risk.get("criteria")
    r_inst = risk.get("instructions")
    if (
        not isinstance(criteria, dict)
        or not isinstance(v_inst, str)
        or not isinstance(r_levels, list)
        or len(r_levels) != 10
        or not all(isinstance(item, str) for item in r_levels)
        or not isinstance(r_inst, str)
    ):
        raise ValueError("referral verdict or risk schema is incomplete")
    for label in VERDICT_LABELS:
        if not isinstance(criteria.get(label), str):
            raise ValueError(f"referral verdict criteria missing {label}")

    wire_model = wire_model_name(provider, model)
    if not wire_model or wire_model.startswith("/") or wire_model.endswith("/"):
        raise ValueError("model identifier resolves to an empty provider model name")

    canonical_verdict = {
        "criteria": {label: criteria[label] for label in VERDICT_LABELS},
        "instructions": v_inst,
        "type": "choice",
    }
    canonical_risk = {
        "criteria": list(r_levels),
        "instructions": r_inst,
        "type": "score",
    }

    if provider in ("typesafe", "perplexity", "cloudflare"):
        return {
            "model": wire_model,
            "questions": {"risk": canonical_risk, "verdict": canonical_verdict},
            "state": state,
        }
    if provider == "google":
        return {
            "input": state,
            "model": wire_model,
            "questions": {"risk": canonical_risk, "verdict": canonical_verdict},
        }
    if provider == "openai":
        choices = [
            {"description": str(criteria[label]), "value": label}
            for label in VERDICT_LABELS
        ]
        levels = [
            {"description": str(text), "label": str(idx)}
            for idx, text in enumerate(r_levels)
        ]
        return {
            "input": state,
            "model": wire_model,
            "questions": [
                {
                    "choices": choices,
                    "instructions": v_inst,
                    "name": "verdict",
                    "type": "choice",
                },
                {
                    "instructions": r_inst,
                    "levels": levels,
                    "name": "risk",
                    "type": "score",
                },
            ],
        }
    raise ValueError(f"unknown provider {provider}")


def _finite_float(val: object) -> float | None:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    try:
        num = float(val)
    except OverflowError:
        return None
    if not math.isfinite(num):
        return None
    return num


def _sanitize_scalar(val: object) -> object:
    if isinstance(val, bool) or val is None or isinstance(val, str):
        return val
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return val if math.isfinite(val) else 2.0
    return "non-scalar"


def _parse_level_index(item: dict[str, object]) -> int | None:
    val_opt: int | None = None
    if "value" in item:
        num = _finite_float(item["value"])
        if num is None or not num.is_integer() or not (0.0 <= num <= 9.0):
            return None
        val_opt = int(num)
    lbl_opt: int | None = None
    if "label" in item:
        lbl = item["label"]
        if not isinstance(lbl, str) or lbl not in {str(i) for i in range(10)}:
            return None
        lbl_opt = int(lbl)
    if val_opt is not None and lbl_opt is not None:
        return val_opt if val_opt == lbl_opt else None
    return val_opt if val_opt is not None else lbl_opt


def _weighted_score(probs: object) -> float | None:
    if isinstance(probs, list):
        if len(probs) != 10:
            return None
        weighted = 0.0
        total = 0.0
        if isinstance(probs[0], dict):
            seen = [False] * 10
            for item in probs:
                if not isinstance(item, dict):
                    return None
                lvl = _parse_level_index(item)
                if lvl is None or seen[lvl]:
                    return None
                seen[lvl] = True
                p = _finite_float(item.get("probability"))
                if p is None or not (0.0 <= p <= 1.0):
                    return None
                weighted += lvl * p
                total += p
        else:
            for idx, item in enumerate(probs):
                if isinstance(item, dict):
                    return None
                p = _finite_float(item)
                if p is None or not (0.0 <= p <= 1.0):
                    return None
                weighted += idx * p
                total += p
        return max(0.0, min(9.0, weighted / total)) if 0.99 <= total <= 1.01 else None
    if isinstance(probs, dict):
        if len(probs) != 10:
            return None
        weighted = 0.0
        total = 0.0
        for idx in range(10):
            key = str(idx)
            if key not in probs:
                return None
            p = _finite_float(probs[key])
            if p is None or not (0.0 <= p <= 1.0):
                return None
            weighted += idx * p
            total += p
        return max(0.0, min(9.0, weighted / total)) if 0.99 <= total <= 1.01 else None
    return None


def _extract_named(items: list[object], target: str) -> tuple[dict[str, object] | None, bool]:
    found: dict[str, object] | None = None
    for item in items:
        if not isinstance(item, dict):
            return None, True
        if item.get("name") == target:
            if found is not None:
                return None, True
            found = item
    return found, False


def _normalize_choice_probs(raw: object) -> object:
    if isinstance(raw, list):
        pairs: dict[str, object] = {}
        for item in raw:
            if not isinstance(item, dict):
                return "malformed-probabilities"
            label = item.get("value") if isinstance(item.get("value"), str) else item.get("label")
            if not isinstance(label, str) or label in pairs or "probability" not in item:
                return "malformed-probabilities"
            pairs[label] = _sanitize_scalar(item["probability"])
        return pairs
    if isinstance(raw, dict):
        return {str(k): _sanitize_scalar(v) for k, v in raw.items()}
    return _sanitize_scalar(raw)


def normalize_provider_reply(raw_text: str, provider: str, pinned_model: str) -> str:
    if not is_valid_model_name(pinned_model):
        raise ValueError("pinned model identifier is outside the valid ASCII shape")
    if not raw_text.strip():
        return ""
    root = strict_loads(raw_text)
    if not isinstance(root, dict):
        return canonical_dumps({"answers": 0, "model": pinned_model})

    if "success" in root:
        if root["success"] is not True:
            raise EnvelopeFailureError("provider envelope reported unsuccessful call")
        if not isinstance(root.get("result"), dict):
            raise EnvelopeFailureError("provider envelope carries no result object")
        payload = root["result"]
    elif provider == "cloudflare" and "result" in root:
        if not isinstance(root["result"], dict):
            raise EnvelopeFailureError("provider envelope carries non-object result")
        payload = root["result"]
    else:
        payload = root

    container = None
    for key in ("answers", "decisions", "output"):
        if key in payload:
            container = payload[key]
            break
    if container is None:
        return canonical_dumps({"answers": {}, "model": pinned_model})

    verdict_raw: object = None
    risk_raw: object = None
    malformed_verdict = False
    if isinstance(container, dict):
        verdict_raw = container.get("verdict")
        risk_raw = container["risk"] if "risk" in container else container.get("score")
    elif isinstance(container, list):
        r_item, r_bad = _extract_named(container, "risk")
        s_item, s_bad = _extract_named(container, "score")
        if not r_bad and not s_bad and not (r_item is not None and s_item is not None):
            risk_raw = r_item if r_item is not None else s_item
        v_item, v_bad = _extract_named(container, "verdict")
        if v_bad:
            malformed_verdict = True
        else:
            verdict_raw = v_item
    else:
        return canonical_dumps({"answers": 0, "model": pinned_model})

    answers: dict[str, object] = {}
    if isinstance(risk_raw, dict):
        raw_score: float | None = None
        invalid_direct = False
        for key in ("score", "expected_score", "expected"):
            if key in risk_raw and risk_raw[key] is not None:
                cand = _finite_float(risk_raw[key])
                if cand is not None and 0.0 <= cand <= 9.0:
                    raw_score = cand
                else:
                    invalid_direct = True
                break
        if raw_score is None and not invalid_direct:
            probs = risk_raw.get("probabilities", risk_raw.get("distribution"))
            raw_score = _weighted_score(probs)
        if raw_score is not None and 0.0 <= raw_score <= 9.0:
            answers["risk"] = {
                "probabilities": {},
                "score": raw_score,
                "type": "score",
            }

    if malformed_verdict:
        answers["verdict"] = "malformed"
    elif verdict_raw is not None:
        if isinstance(verdict_raw, dict):
            choice = verdict_raw.get("choice", verdict_raw.get("selected"))
            probs = verdict_raw.get("probabilities", verdict_raw.get("distribution"))
            answers["verdict"] = {
                "choice": _sanitize_scalar(choice),
                "probabilities": _normalize_choice_probs(probs),
                "type": "choice",
            }
        else:
            answers["verdict"] = _sanitize_scalar(verdict_raw)

    return canonical_dumps({"answers": answers, "model": pinned_model})


def _clean_secret(env_names: tuple[str, ...], label: str) -> str:
    for name in env_names:
        val = os.environ.get(name, "").strip()
        if val:
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in val):
                raise ValueError(f"{name} contains control characters")
            return val
    raise ValueError(f"missing API key for {label}")


def auth_headers(provider: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if provider == "typesafe":
        key = _clean_secret(("TYPESAFE_API_KEY", "DECISION_API_KEY"), "typesafe")
        headers["Authorization"] = f"Bearer {key}"
    elif provider == "google":
        key = _clean_secret(("GEMINI_API_KEY", "GOOGLE_API_KEY", "DECISION_API_KEY"), "google")
        headers["x-goog-api-key"] = key
    elif provider == "openai":
        key = _clean_secret(("OPENAI_API_KEY", "DECISION_API_KEY"), "openai")
        headers["Authorization"] = f"Bearer {key}"
    elif provider == "perplexity":
        key = _clean_secret(("PERPLEXITY_API_KEY", "DECISION_API_KEY"), "perplexity")
        headers["Authorization"] = f"Bearer {key}"
    elif provider == "cloudflare":
        key = _clean_secret(("CLOUDFLARE_API_TOKEN", "DECISION_API_KEY"), "cloudflare")
        headers["Authorization"] = f"Bearer {key}"
    return headers


class _HttpsSameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code not in (307, 308):
            raise urllib.error.URLError(f"refusing status {code} redirect on POST consultation")
        validate_https_url(newurl)
        orig = urllib.parse.urlsplit(req.full_url)
        dest = urllib.parse.urlsplit(newurl)
        if dest.scheme != "https" or dest.netloc != orig.netloc:
            raise urllib.error.URLError("refusing cross-host or non-HTTPS redirect")
        return urllib.request.Request(
            newurl,
            data=req.data,
            headers=dict(req.header_items()),
            method="POST",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        choices=("typesafe", "google", "openai", "perplexity", "cloudflare"),
        help="Override auto-detected System One provider dialect",
    )
    parser.add_argument("--input", help="Read referral request from file instead of stdin")
    parser.add_argument("--model", help="Override model identifier sent to the provider")
    parser.add_argument("--api-url", help="Override HTTPS endpoint URL")
    parser.add_argument("--timeout", type=float, default=25.0, help="HTTP timeout in seconds")
    parser.add_argument("--offline-reply", help="Read raw provider response from file without network")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print formatted provider request metadata without making a network call",
    )
    args = parser.parse_args(argv)

    try:
        if args.input:
            with open(args.input, encoding="utf-8") as in_handle:
                raw_in = in_handle.read()
        else:
            raw_in = sys.stdin.read()
        doc = strict_loads(raw_in)
        if not isinstance(doc, dict):
            raise ValueError("referral request must be a JSON object")
        pinned_model = doc.get("model")
        if not is_valid_model_name(pinned_model):
            raise ValueError("referral request model is invalid")
        assert isinstance(pinned_model, str)
        request_model = args.model or pinned_model
        if not is_valid_model_name(request_model):
            raise ValueError("override model is invalid")
        provider = args.provider or detect_provider(request_model)
        wire_req = format_provider_request(doc, provider, request_model)
        body_bytes = canonical_dumps(wire_req).encode("utf-8")

        if args.dry_run:
            endpoint = resolve_endpoint(provider, request_model, args.api_url)
            sys.stdout.write(
                canonical_dumps(
                    {
                        "endpoint": endpoint,
                        "provider": provider,
                        "wire_request": wire_req,
                    }
                )
                + "\n"
            )
            return 0

        reply_model = request_model if args.model else pinned_model
        if args.offline_reply:
            with open(args.offline_reply, encoding="utf-8") as handle:
                raw_reply = handle.read(MAX_REPLY_BYTES + 1)
            if len(raw_reply.encode("utf-8")) > MAX_REPLY_BYTES:
                sys.stdout.write("malformed oversized provider reply\n")
                return 0
        else:
            endpoint = resolve_endpoint(provider, request_model, args.api_url)
            headers = auth_headers(provider)
            opener = urllib.request.build_opener(_HttpsSameHostRedirectHandler)
            http_req = urllib.request.Request(endpoint, data=body_bytes, headers=headers, method="POST")
            with opener.open(http_req, timeout=args.timeout) as resp:
                raw_bytes = resp.read(MAX_REPLY_BYTES + 1)
            if len(raw_bytes) > MAX_REPLY_BYTES:
                sys.stdout.write("malformed oversized provider reply\n")
                return 0
            try:
                raw_reply = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                sys.stdout.write("malformed non-utf8 provider reply\n")
                return 0

        try:
            normalized = normalize_provider_reply(raw_reply, provider, reply_model)
        except MalformedReplyError:
            sys.stdout.write("malformed provider reply\n")
            return 0
        except EnvelopeFailureError as exc:
            sys.stderr.write(f"decision_judge envelope error {exc}\n")
            return 1

        sys.stdout.write(normalized + ("\n" if normalized else ""))
        return 0
    except urllib.error.URLError as exc:
        sys.stderr.write(f"decision_judge transport error {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"decision_judge error {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
