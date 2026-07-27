# Attestation Proxy Napkin

## Confidentiality and diagnostics

- AA token failures may report bounded transport shape (timeout, connect,
  HTTP status, content type, JSON decode), but never include upstream response
  bodies, bearer tokens, evidence, request query data, or raw URLs.
- Check HTTP status before decoding an AA token response. Non-success HTML or
  proxy error pages are transport failures, not malformed token payloads.
- Runtime-data-bound KBS tokens must bypass the reusable AA token cache.

## Verification

- Exercise AA response parsing with a local HTTP server covering non-2xx,
  wrong content type, malformed JSON, and a valid token payload.
