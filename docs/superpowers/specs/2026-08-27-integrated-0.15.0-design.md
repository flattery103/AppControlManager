# AppControl Manager 0.15.0 Integrated Feature Design

## Goal

Advance directly from 0.13.1 to a consolidated 0.15.0 release that completes the practical 0.13.x–0.15.x roadmap without performing the deferred final tenant/security audit.

## Existing capabilities retained

The 0.13.1 source already contains reusable enrollment tokens, signed-command claim/replay protection, device groups, scoped allow/block policies, publisher/product identity matching, silent first-install switches, agent release storage, scoped deployments, rollout percentage targeting, installer downloads, and managed agent update commands. These are preserved and versioned forward rather than rebuilt.

## New work in 0.15.0

### 1. Production signing pipeline

GitHub Release builds use Microsoft Azure Artifact Signing. The release workflow publishes service and tray binaries first, signs and verifies those binaries, then builds the managed agent ZIP and embedded installer from the signed payload, signs and verifies the final installer, computes checksums, and only then creates the GitHub Release. OIDC is used through `azure/login`; release signing therefore requires the configured Azure/GitHub secrets and Artifact Signing profile.

Local/ordinary CI builds remain unsigned so developers can build without Azure credentials. The release packaging stage explicitly refuses to create a release package when `-RequireSignedPayload` is specified and the service/tray signatures are invalid.

### 2. Server update management UI

Global administrators get an Administration → Server Updates page. It shows current server version, latest GitHub Release version, repository, release URL, publication time, release notes, required asset availability, GitHub connectivity status, and whether an update is available. The page can refresh metadata without changing the server.

Installation is launched as a detached systemd transient unit so restarting the AppControl Manager service does not terminate its own updater. The UI reports the last updater log and active/finished status. Only global administrators can start server self-update.

### 3. Automatic matching agent-release import

The GitHub updater downloads and verifies the agent ZIP, agent SHA256, Windows installer, and installer SHA256 from the same GitHub Release. After server upgrade health succeeds, it imports those verified files into `agent_releases` as the stable release if that version is not already present. Existing releases are left intact and duplicate imports are idempotent.

The server update page also reports whether the matching stable agent release is already imported. Manual agent upload remains available as a fallback.

### 4. Policy-management completion

The existing scoped policy engine remains authoritative. Approval/block actions retain Device, Group, Organization, and Global scope choices (Global restricted to global administrators). Application Policies remains the durable management surface for disabling/deleting scoped policies. The release documentation explicitly records publisher/product matching and scoped policy behavior as a 0.15.0 production feature.

## Non-goals

- No deep cross-tenant penetration-style authorization audit in this milestone.
- No automatic production-wide server update scheduling.
- No automatic endpoint rollout ring promotion beyond the existing scoped deployment/rollout percentage system.
- No short-lived or single-use enrollment tokens.
- No WDAC policy-performance rewrite; that remains the next major milestone after 0.15.0.

## Compatibility

- Existing SQLite databases migrate in place.
- Existing 0.13.x Windows agents continue to report and receive commands.
- Existing manual agent releases/deployments continue to work.
- Existing GitHub updater environment variables remain supported.
- New server-update metadata uses only Python standard-library HTTP clients; no new runtime Python dependency is required.
