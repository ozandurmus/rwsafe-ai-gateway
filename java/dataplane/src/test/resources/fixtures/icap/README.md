# Synthetic ICAP fixtures

Encapsulated HTTP requests per platform, surface and step (ICAP spec §5). Every body is synthetic: `{{PROMPT}}` is filled
by the test or by `tools/icap/replay.py`, and identifiers with valid checksums or secret shapes are generated at runtime,
never committed (AGENTS.md 4.5). `{{LEN}}` becomes the body length. The head uses LF in the file; the harness sends CRLF.
