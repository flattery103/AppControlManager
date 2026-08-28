# Installation Mode Design

## Goal

Add a safe, time-limited installation workflow for software installers that legitimately launch many executables, DLLs, MSI helpers, services, and update components. End users can request an installation window from the blocked-application popup; administrators approve the requested duration; the timer starts only when the end user explicitly starts the approved window. Administrators can also start Installation Mode directly from a device page.

## User workflow

1. Windows App Control blocks an installer or application component.
2. The endpoint popup offers both **Request Access** and **Request Installation**.
3. **Request Access** preserves the existing per-application approval flow.
4. **Request Installation** creates a separate Installation Request containing the blocked executable context, user, device, reason, and request time. It does not weaken enforcement.
5. An administrator sees the Installation Request as a distinct request type and can approve 15, 30, 60, or a custom duration up to 240 minutes, or deny it.
6. An approved user-requested installation window remains activatable for four hours. Enforcement remains active while waiting.
7. The endpoint user receives an **Installation Approved** popup. Clicking **Start Installation** begins the approved timer; **Not Now** leaves enforcement unchanged and the approval available until its four-hour activation deadline.
8. Starting the installation changes the device to Audit/Learning mode, resets the learning cursor to that instant, and records an Installation Mode session locally and on the server.
9. The endpoint user sees an obvious Installation Mode popup/status with the remaining time and a **Finish Installation Early** action.
10. When the timer expires, or the user/admin ends it early, AppControl Manager finalizes the learned delta and restores Enforcement.
11. If learned-fragment finalization fails, AppControl Manager still restores Enforcement using the prior known-good authorization baseline and records the unresolved/failure result. Installation Mode must never remain permissive indefinitely because learning finalization failed.

## Administrator workflow

### User-requested installation

The management console displays Installation Requests separately from ordinary access approvals. Pending Installation Requests show device, requesting user, triggering executable/product, reason, and request time. Approval selects a duration. Approval itself does not start Installation Mode.

### Manual installation mode

The device page includes **Start Installation Mode** with 15, 30, 60, and custom durations (maximum 240 minutes). Administrator-initiated mode starts as soon as the endpoint receives the command. While active, the device page displays an obvious Installation Mode banner, who/what initiated it, duration/end time, and **End Installation Mode Now**.

## Security model

- Endpoint users can request Installation Mode but cannot enable it without an administrator approval.
- User-requested approvals expire four hours after approval if not activated.
- Installation Mode is device-wide for its active duration; anything executed during the window may be learned. The UI must clearly communicate this.
- Default duration is 15 minutes; maximum is 240 minutes.
- The active timer and expiration enforcement live on the endpoint, not in the browser or server.
- Endpoint restart, browser closure, or temporary server loss must not extend the permissive window.
- On expiration, Enforcement restoration takes priority over complete learning. If rule generation/finalization cannot finish, restore Enforcement anyway and report the problem.
- Existing explicit BLOCK policies remain management records; Installation Mode is intended for trusted maintenance activity, not a way for endpoint users to override administrator decisions.
- Every request, approval, activation, manual start, early finish, automatic expiration, completion, failure, and return to Enforcement is auditable.

## Data model

Create `installation_requests` with these core fields:

- `id`, `device_id`
- triggering `file_path`, `sha256`, `publisher`, `product_name`, `file_version`
- `reason`, `requested_by`
- `source` (`user` or `admin`)
- `status` (`pending`, `approved`, `starting`, `active`, `ending`, `completed`, `denied`, `expired`, `failed`)
- `duration_minutes`
- `activation_expires_at`
- `approved_at`, `approved_by`
- `started_at`, `ends_at`, `completed_at`
- `decision_note`, `created_at`

User requests and administrator-initiated sessions share this table so history and audit presentation remain coherent.

## Endpoint architecture

Add a local installation-mode state file separate from normal agent state. It records whether Installation Mode is active, request/session ID, start/end timestamps, duration, trigger, and any server report that still needs to be delivered.

The existing LocalSystem service owns Installation Mode. It uses the existing policy helper to enter Learning/Audit mode. During the active window, normal learning-event upload and the 0.16.5 Local Service rule worker continue preparing rule fragments incrementally.

A maintenance-loop expiration check runs independently of server connectivity. When the local deadline is reached it finalizes learning and restores Enforcement. On finalization failure it executes a dedicated force-enforcement fallback that flips the base policy back to Enforcement without requiring unresolved new learned fragments.

## Commands and APIs

Add validated endpoint commands:

- `start_installation_mode`: request/session ID, duration, trigger/actor metadata.
- `end_installation_mode`: request/session ID and reason.

Add agent-authenticated APIs for creating/listing/starting/finishing/reporting installation requests. Starting an approved user request queues `start_installation_mode`; its timer begins only after the endpoint actually enters Installation Mode.

The endpoint reports authoritative `started_at` and `ends_at` values after mode activation. Automatic local expiration reports completion/failure even though it is not initiated by a server command. Failed reports are retained locally and retried when connectivity returns.

## UI

### Endpoint blocked popup

Add **Request Installation** next to **Request Access** for blocked application/session popups. Submitting it closes/replaces the normal access workflow with an Installation Request status.

### Endpoint approval popup

Approved installation request popup:

- explains approved duration and four-hour start deadline
- **Start Installation**
- **Not Now**

Active installation popup/status:

- `INSTALLATION MODE ACTIVE`
- live countdown
- **Finish Installation Early**

### Server

- Installation Requests are visually distinct from ordinary application approvals.
- Device page has manual start controls.
- Active/starting installation state is shown prominently on the device page.
- Device mode controls redirect back to the same device page after actions.

## Version and release scope

This is a new architectural feature and should release as **AppControl Manager 0.17.0**.

Both server and Windows agent change. The release continues to use the existing GitHub build/signing pipeline and matching-agent automatic import; no manual agent upload should be required.

Deferred from this release: special classification/exclusion of `.NET` single-file extraction artifacts and unrelated approval-policy lifecycle cleanup.
