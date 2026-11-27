# Changelog

All notable changes to portcullis are recorded in this file.

## 0.2.0 on 2026-11-26

- Default decision model advanced to `jev-1.14.0` with optional `judgment.model` defaulting in `portcullis-policy/1` while keeping all 258 recorded `jev-1.13.0` judgment fixtures untouched under `PC-35`.
- First-class provider wire codecs and `JUDGE_MODELS` support added across TypeSafe (`jev-1.14.0`, `jev-1.13.0`), Google (`gemini-decision-1`), OpenAI (`gpt-6-luna`, `gpt-oss-safeguard-120b`, `gpt-oss-safeguard-20b`), Perplexity (`pplx-decider-v1.3`, `pplx-decider-latest`, `pplx-decider-flash-v1.3`, `pplx-decider-flash-latest`), and Cloudflare (`@cf/cloudflare/clef`, `@cf/cloudflare/clef-flash`, `clef`, `clef-flash`), plus standalone HTTPS helper `examples/decision_judge.py`.
- Destination `path2` matching (`exact`, `prefix`, `glob`) over raw and lexically normalized destination paths on `move` file calls, plus top-level `-V` and `--version` command line flags under `PC-36`.
- Cross-platform lock identity, stack-safe deep Python value conversion, and portability CI across Linux, macOS, and Windows, with PyO3 `0.30` `abi3-py39` bindings, PEP 561 `py.typed` and `__init__.pyi` type stubs, and automated `v0.2.0` release workflows under `PC-37`.

## 0.1.0 on 2026-11-15

- Deterministic tool-call decision gate over `portcullis-policy/1` and `portcullis-call/1` across shell, file, and network calls, with fixed evaluation order, rewrites, canonical digests, and locked append-only audit logging (`PC-1` through `PC-12`).
- Decision model referral (`portcullis-decision/2`), confidence threshold combination, five failure classes, risk-scored sampling audit (`portcullis-audit/1`), and calibrated denial doctrine (`PC-13` through `PC-34`).
