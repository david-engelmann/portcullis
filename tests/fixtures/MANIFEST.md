# Fixture manifest

The documents in this folder were written by the Python implementation of portcullis on main and frozen here as equivalence ground truth for the Rust port that opens Round 2. A producer script drove the public library surface of that implementation, loading policies, evaluating calls at the fixed instant 2026-11-02T10:00:00+00:00, and appending decisions to an audit log, and the files below are its output, copied without editing. Every document is synthetic and written for this repo. The Rust fixture suite checks the hashes recorded here, loads each policy, evaluates each recorded case and compares the decision field by field against the expected file, reads the audit log back whole, and appends the network decision to its own copy of the log and compares the bytes against the continued log the Python implementation produced.

## Inventory

- audit-log-continued.jsonl, sha256 f8cbfc1f515dca0e0b82bf5114ed4d98f2777462559fba854144a9989b6ec176, 1538 bytes
- audit-log.jsonl, sha256 16a3c21631e8066197d91d74f38d4a53fd09aa3e2b79593e8b6392ffd92769cf, 1235 bytes
- call-file-normalized.json, sha256 8e4fd30cc0d11d183e9e5e7ff0082071dc367d9fcf21b06c86fd986bae409191, 106 bytes
- call-file-rewrite.json, sha256 cf05a0122cee77987d1df9e8c4ac70458b76e567c9d3399375c2e38e7cd28327, 112 bytes
- call-malformed.json, sha256 7055719efa41d98fb164d77bdda4dfce22a13edcf4af519e8b08a9b44715ec61, 55 bytes
- call-network-explicit.json, sha256 6ddfd168e8c6a848249da037519b165ffac77619f4c10ec2bf69e9a2df2feab9, 125 bytes
- call-network-url.json, sha256 25be65a336093492b879d9a291d284d4c29e01a2554727f857a96903f58796a9, 119 bytes
- call-shell-allow.json, sha256 7496d770f3317c16720a718917af89a31cbb31a0063287fbc33587381913fcb3, 92 bytes
- call-shell-deny.json, sha256 516880845b9c63666a60b705f9a4810a674973ee84b92b1e9cfb1bb2d654b2a3, 90 bytes
- call-shell-interpreter.json, sha256 7649bc9685ea3f1cd55a68e36b1e6770a6d73a09e9eec5be4b9d6be1d9fca1cb, 106 bytes
- expected/policy-default-allow--call-file-normalized.json, sha256 37d3b25b3677bf9243f25eccca6e77000d5afc2fafe97a754b48dbb3670c68d7, 301 bytes
- expected/policy-default-allow--call-shell-allow.json, sha256 46cf9298abb2c59796e3e7c59e663504c8f3f6fbcc4c2933670963da21c92ba5, 301 bytes
- expected/policy-full--call-file-normalized.json, sha256 88272481011c7273fdd2da5ab187333a796e5e2304799d50fc4ddd4f61c71d61, 351 bytes
- expected/policy-full--call-file-rewrite.json, sha256 b755502cc321d860d9126e0d9fb82b2767ace71ad83462b454e027dc68f6ed60, 466 bytes
- expected/policy-full--call-malformed.json, sha256 f06e67147eca065a5074675a7c551c65e9f6179df6b201d2dc3d3ee93efcc112, 302 bytes
- expected/policy-full--call-network-explicit.json, sha256 4d6c7a446d345b6b51a73b84088b50b54004610bc581d28d8e9014cac1b6fc59, 300 bytes
- expected/policy-full--call-network-url.json, sha256 4e89e76e82ce26a1d98f541e41645b2722127f2dc94547c3db89511c3c8d0c6a, 351 bytes
- expected/policy-full--call-shell-allow.json, sha256 6e36c65b1e112ed50d84c0bf5903f140968d7925906a503cf00672101ace5cd9, 335 bytes
- expected/policy-full--call-shell-deny.json, sha256 952d056c133c09b3a0b2832e1993ab085664d513f443e3c7d504cd1d53dd3204, 345 bytes
- expected/policy-full--call-shell-interpreter.json, sha256 6a80cd81d4e1b9dcdd8c4782b2169dee26c2ccde793b0ea40d2813eaaf9343d2, 299 bytes
- policy-broken.json, sha256 e397d1f051f94cb498bb0dd5f40b61b0077907e199a0c125a484799605d7be7c, 204 bytes
- policy-default-allow.json, sha256 c76ea76282cc9fd33009ac9f3d02f091928a435cfb3f2a9e439b30d2ff9f05fe, 294 bytes
- policy-full.json, sha256 c39b69ef36b7af9cbef08aae70fa8b60b4cf7ecd645a60ce27a3738858a7b15f, 1333 bytes

## Productions and truths

The full policy declares a deny default and five rules covering a shell deny, a shell allow, a file deny on an exact path, a file rewrite into a staging path, and a network allow on one host at port 443. The default allow policy declares an allow default and one file deny on the delete operation. The broken policy carries one rule whose match holds no condition, and loading it under the Python implementation refuses with the message that the match of rule empty holds no condition.

The recorded cases decide as follows at the fixed instant. The full policy allows the listing call from its allow rule, denies the removal call from its deny rule, denies the interpreter call from the default with the interpreter flag set, rewrites the staging write from its rewrite rule, denies the normalized secret read from its file deny rule, allows the url call from its network allow rule, denies the explicit network call from the default, and denies the malformed call as malformed. The default allow policy allows the listing call from the default and allows the normalized secret read from the default, because its only rule speaks to the delete operation.

The audit log holds the first four decisions of the full policy in case order, one canonical line each, appended by the Python implementation under its lock. The continued log is a copy of that log with the network decision appended by the same implementation, and it is the byte target for a Rust append over a copy of the first log.
