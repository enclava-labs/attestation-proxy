# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-08-05] Run the container size gate before merging release-affecting changes**
   Do instead: build the exact PR head with the Dockerfile and verify the image is below 16 MiB; PR CI runs only Rust checks, while the Docker gate first runs during publication.
2. **[2026-07-10] Verify recovery changes against persisted storage semantics**
   Do instead: test both locked and already-unlocked recovery paths, including valid-but-wrong BIP39 mnemonics and persistence ordering.

## Shell & Command Reliability
1. **[2026-07-10] Prefer ripgrep for repository discovery**
   Do instead: use `rg` and `rg --files` for code and test discovery.

## Domain Behavior Guardrails
1. **[2026-07-10] Never commit owner-seed material before semantic verification**
   Do instead: verify a recovery seed against durable app identity before replacing its encrypted envelope.
2. **[2026-08-03] Keep `/aa/token` identity-only**
   Do instead: ignore `runtime_data` on the token route and never claim that it proves receipt-key binding.
3. **[2026-08-03] Bind receipt keys through independently verified evidence**
   Do instead: use the embedded `/aa/evidence` proof that KBS verifies, and retry only typed KBS `503` verifier outages—not authorization denials.

## Confidentiality & Diagnostics
1. **[2026-08-03] Bound attestation transport diagnostics**
   Do instead: report only timeout/connect/status/content-type/JSON-decode shape; never expose response bodies, bearer tokens, evidence, query data, or raw URLs.
2. **[2026-08-03] Classify upstream HTTP failures before decoding**
   Do instead: check status first so non-success HTML and proxy error pages remain transport failures rather than malformed-token errors.
3. **[2026-08-03] Exercise the real AA response boundary**
   Do instead: test response parsing through a local HTTP server for non-2xx, wrong content type, malformed JSON, and a valid token payload.

## User Directives
1. **[2026-07-10] Keep issue fixes isolated**
   Do instead: use one branch and PR per issue, preserving unrelated worktrees and changes.
