# 0.18.1 Learning Noise Cleanup Design

## Goal

Keep long-running Learning mode operationally quiet without weakening Windows App Control enforcement or trusting writable temporary directories.

## Design

The agent will watch Code Integrity audit events (3076) continuously and copy an observed executable into a protected ProgramData cache while it still exists. Background FilePublisher or hash rule generation will use that preserved copy when the original path has disappeared. The cache is input-only: cached files are never executed, and existing publisher/product/hash requirements remain unchanged.

A representative that disappears before it can be preserved is normal transient churn, not an infrastructure failure. Its rule becomes `expired`, is excluded from pending/failed counts, and is not retried. On upgrade, legacy failed entries carrying the exact missing-representative error are migrated to `expired`; genuine ConfigCI, worker, validation, and policy-install failures remain failed and retryable.

Endpoint prompts remain fail-closed. No TEMP path is trusted. Repeated Code Integrity blocks for the same file identity are deduplicated for two minutes, and related components can join the active request window for longer, while every block still reaches server telemetry.

## Security Boundaries

- Never add a wildcard TEMP allow rule or weaken WDAC writable-path protection.
- Never execute a preserved file.
- Prefer signed FilePublisher/product identity; otherwise retain exact SHA-256 behavior.
- Unknown or unsigned transient executables remain blocked in Enforcement.
- Only missing representative files become `expired`; all other exceptions remain failures.

## Verification

- Regression tests cover cache wiring, fallback ordering, neutral expiry, legacy migration, retry isolation, and prompt deduplication.
- Run the full Python suite, whitespace validation, and Windows behavior/build tests where the required Windows toolchain is available.
