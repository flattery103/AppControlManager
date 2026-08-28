using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class LocalRequestServer
{
    private readonly ApiClient _api;
    private readonly FileLogger _log;
    private readonly BlockedFileCache _cache;
    private readonly PolicyProgressTracker _progress;
    private readonly InstallationModeManager _installationMode;

    public LocalRequestServer(ApiClient api, FileLogger log, BlockedFileCache cache, PolicyProgressTracker progress, InstallationModeManager installationMode)
    {
        _api = api;
        _log = log;
        _cache = cache;
        _progress = progress;
        _installationMode = installationMode;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(ct);
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                var line = await reader.ReadLineAsync(ct);
                PipeResponse response;
                try
                {
                    var req = JsonSerializer.Deserialize<PipeRequest>(line ?? "{}", new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new PipeRequest();
                    response = await HandleAsync(req, ct);
                }
                catch (Exception ex)
                {
                    response = new PipeResponse { Ok = false, Message = ex.Message };
                }
                await writer.WriteLineAsync(JsonSerializer.Serialize(response));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.Write("pipe: " + ex.Message);
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task<PipeResponse> HandleAsync(PipeRequest req, CancellationToken ct)
    {
        if (string.Equals(req.Action, "capture", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(req.FilePath))
                return new PipeResponse { Ok = false, Message = "Blocked file path was empty." };
            var capturedSnapshot = _cache.Capture(req.RecordId ?? 0, req.FilePath, req.ParentPath);
            return new PipeResponse
            {
                Ok = true,
                Snapshot = capturedSnapshot,
                Message = capturedSnapshot.CachedPath is not null
                    ? "Blocked component preserved for approval."
                    : "Blocked component metadata captured; file copy was unavailable."
            };
        }
        if (string.Equals(req.Action, "disposition", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(req.FilePath))
                return new PipeResponse { Ok = false, Message = "Blocked file path was empty." };

            var dispositionOriginalPath = DevicePathResolver.Resolve(req.FilePath) ?? req.FilePath;
            var snapshot = req.RecordId.HasValue ? _cache.Get(req.RecordId.Value) : null;
            var dispositionSourcePath = File.Exists(dispositionOriginalPath)
                ? dispositionOriginalPath
                : (snapshot?.CachedPath is not null && File.Exists(snapshot.CachedPath) ? snapshot.CachedPath : null);
            var dispositionMeta = dispositionSourcePath is not null ? FileMetadataReader.Read(dispositionSourcePath) : null;
            var disposition = await _api.GetDispositionAsync(new ApplicationDispositionRequest
            {
                FilePath = dispositionOriginalPath,
                Sha256 = dispositionMeta?.Sha256 ?? snapshot?.Sha256,
                Publisher = dispositionMeta?.Publisher ?? snapshot?.Publisher,
                ProductName = dispositionMeta?.ProductName ?? snapshot?.ProductName,
                FileVersion = dispositionMeta?.FileVersion ?? snapshot?.FileVersion,
                RequestedBy = req.RequestedBy
            }, ct);

            return new PipeResponse
            {
                Ok = disposition.Ok,
                Disposition = disposition.State,
                RequestId = disposition.RequestId,
                RequestStatus = disposition.RequestStatus,
                DecisionNote = disposition.DecisionNote,
                Message = disposition.DecisionNote ?? disposition.State
            };
        }

        if (string.Equals(req.Action, "progress", StringComparison.OrdinalIgnoreCase))
        {
            return new PipeResponse
            {
                Ok = true,
                Progress = _progress.Snapshot(),
                Message = "Current local policy-operation progress."
            };
        }

        if (string.Equals(req.Action, "status", StringComparison.OrdinalIgnoreCase))
        {
            var mode = PolicyInspector.GetMode();
            var requests = await _api.GetRequestsAsync(req.RequestedBy, ct);
            var installations = await _api.GetInstallationsAsync(req.RequestedBy, ct);
            var active = requests.Count(IsActive);
            return new PipeResponse
            {
                Ok = true,
                Mode = mode,
                Requests = requests,
                Installations = installations,
                InstallationMode = _installationMode.Snapshot(),
                Message = active == 0 ? $"AppControl Manager mode: {mode}\nNo current approval requests." : $"AppControl Manager mode: {mode}\nCurrent approval requests: {active}"
            };
        }

        if (string.Equals(req.Action, "requests", StringComparison.OrdinalIgnoreCase))
        {
            var requests = await _api.GetRequestsAsync(req.RequestedBy, ct);
            return new PipeResponse { Ok = true, Requests = requests, Message = $"Returned {requests.Count} request(s)." };
        }

        if (string.Equals(req.Action, "start_installation", StringComparison.OrdinalIgnoreCase))
        {
            if (!req.InstallationId.HasValue || req.InstallationId.Value <= 0) return new PipeResponse { Ok=false, Message="Installation request ID was missing." };
            var result = await _api.StartInstallationAsync(req.InstallationId.Value, new InstallationStartRequest { RequestedBy=req.RequestedBy }, ct);
            return new PipeResponse { Ok=result.Ok, InstallationId=result.InstallationId, RequestStatus=result.Status, Message="Installation start requested. The endpoint will enter Installation Mode now." };
        }
        if (string.Equals(req.Action, "finish_installation", StringComparison.OrdinalIgnoreCase))
        {
            var state=_installationMode.Snapshot();
            var id=req.InstallationId ?? (state.InstallationId > 0 ? state.InstallationId : null);
            if (!id.HasValue) return new PipeResponse { Ok=false, Message="No active Installation Mode session was found." };
            var result=await _api.FinishInstallationAsync(id.Value,new InstallationStartRequest { RequestedBy=req.RequestedBy },ct);
            return new PipeResponse { Ok=result.Ok, InstallationId=result.InstallationId, RequestStatus=result.Status, Message="Installation Mode is being finalized." };
        }

        if (string.Equals(req.Action, "block_session", StringComparison.OrdinalIgnoreCase))
        {
            var ids = req.ComponentRecordIds.Where(x => x > 0).Distinct().ToArray();
            if (ids.Length == 0)
                return new PipeResponse { Ok = false, Message = "No blocked components were available to block." };

            // Prefer the primary executable for a device-only user block. Blocking the launch EXE is
            // enough to make future attempts silent while avoiding broad deny rules for every helper DLL.
            var snapshots = ids.Select(id => _cache.Get(id)).Where(x => x is not null).Cast<BlockedSnapshot>().ToList();
            var chosen = snapshots.FirstOrDefault(x => Path.GetExtension(x.OriginalPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                         ?? snapshots.FirstOrDefault();
            if (chosen is null)
                return new PipeResponse { Ok = false, Message = "The blocked application metadata is no longer available. Re-run it and try again." };

            var blockOriginalPath = DevicePathResolver.Resolve(chosen.OriginalPath) ?? chosen.OriginalPath;
            var blockSourcePath = File.Exists(blockOriginalPath)
                ? blockOriginalPath
                : (chosen.CachedPath is not null && File.Exists(chosen.CachedPath) ? chosen.CachedPath : null);
            if (blockSourcePath is null)
                return new PipeResponse { Ok = false, Message = "The blocked application disappeared before AppControl Manager could preserve it. Re-run it and try again." };

            var blockMeta = FileMetadataReader.Read(blockSourcePath);
            var result = await _api.RequestUserBlockAsync(new ApprovalRequest
            {
                FilePath = blockOriginalPath,
                PolicySourcePath = string.Equals(blockSourcePath, blockOriginalPath, StringComparison.OrdinalIgnoreCase) ? null : blockSourcePath,
                Sha256 = blockMeta.Sha256 ?? chosen.Sha256,
                Publisher = blockMeta.Publisher ?? chosen.Publisher,
                ProductName = blockMeta.ProductName ?? chosen.ProductName,
                FileVersion = blockMeta.FileVersion ?? chosen.FileVersion,
                Reason = req.Reason,
                RequestedBy = req.RequestedBy
            }, ct);
            return new PipeResponse
            {
                Ok = result.Ok,
                Blocked = true,
                Disposition = result.State,
                DecisionNote = result.DecisionNote,
                Message = result.DecisionNote ?? "Blocked on this device."
            };
        }

        if (string.Equals(req.Action, "request_installation_session", StringComparison.OrdinalIgnoreCase))
        {
            var ids=req.ComponentRecordIds.Where(x=>x>0).Distinct().ToArray();
            var snapshots=ids.Select(id=>_cache.Get(id)).Where(x=>x is not null).Cast<BlockedSnapshot>().ToList();
            var chosen=snapshots.FirstOrDefault(x=>Path.GetExtension(x.OriginalPath).Equals(".exe",StringComparison.OrdinalIgnoreCase)) ?? snapshots.FirstOrDefault();
            if (chosen is null) return new PipeResponse { Ok=false, Message="The installer metadata is no longer available. Re-run the installer and try again." };
            var original=DevicePathResolver.Resolve(chosen.OriginalPath) ?? chosen.OriginalPath;
            var source=File.Exists(original) ? original : (chosen.CachedPath is not null && File.Exists(chosen.CachedPath) ? chosen.CachedPath : null);
            if (source is null) return new PipeResponse { Ok=false, Message="The installer disappeared before AppControl Manager could preserve it." };
            var installationMeta=FileMetadataReader.Read(source);
            var result=await _api.RequestInstallationAsync(new ApprovalRequest { FilePath=original, PolicySourcePath=string.Equals(source,original,StringComparison.OrdinalIgnoreCase)?null:source, Sha256=installationMeta.Sha256??chosen.Sha256, Publisher=installationMeta.Publisher??chosen.Publisher, ProductName=installationMeta.ProductName??chosen.ProductName, FileVersion=installationMeta.FileVersion??chosen.FileVersion, Reason=req.Reason, RequestedBy=req.RequestedBy },ct);
            return new PipeResponse { Ok=result.Ok, InstallationId=result.InstallationId, RequestStatus=result.Status, Duplicate=result.Duplicate, Message=result.Duplicate ? $"Installation request {result.InstallationId} already exists and is {result.Status}." : $"Installation request {result.InstallationId} submitted." };
        }

        if (string.Equals(req.Action, "request_session", StringComparison.OrdinalIgnoreCase))
        {
            var ids = req.ComponentRecordIds.Where(x => x > 0).Distinct().ToArray();
            if (ids.Length == 0)
                return new PipeResponse { Ok = false, Message = "No blocked components were available for this request." };

            var components = new List<ApprovalComponent>();
            foreach (var id in ids)
            {
                var snapshot = _cache.Get(id);
                if (snapshot is null) continue;
                var sessionOriginalPath = DevicePathResolver.Resolve(snapshot.OriginalPath) ?? snapshot.OriginalPath;
                var sessionSourcePath = File.Exists(sessionOriginalPath)
                    ? sessionOriginalPath
                    : (snapshot.CachedPath is not null && File.Exists(snapshot.CachedPath) ? snapshot.CachedPath : null);
                if (sessionSourcePath is null) continue;
                var sessionMeta = FileMetadataReader.Read(sessionSourcePath);
                components.Add(new ApprovalComponent
                {
                    FilePath = sessionOriginalPath,
                    PolicySourcePath = string.Equals(sessionSourcePath, sessionOriginalPath, StringComparison.OrdinalIgnoreCase) ? null : sessionSourcePath,
                    Sha256 = sessionMeta.Sha256 ?? snapshot.Sha256,
                    Publisher = sessionMeta.Publisher ?? snapshot.Publisher,
                    ProductName = sessionMeta.ProductName ?? snapshot.ProductName,
                    FileVersion = sessionMeta.FileVersion ?? snapshot.FileVersion,
                    ParentPath = snapshot.ParentPath,
                    RecordId = snapshot.RecordId
                });
            }
            if (components.Count == 0)
                return new PipeResponse
                {
                    Ok = false,
                    Message = "The blocked components disappeared before AppControl Manager could preserve them. Re-run the original application or installer and request access again."
                };

            var session = new ApprovalSessionRequest
            {
                Components = components,
                Reason = req.Reason,
                RequestedBy = req.RequestedBy,
                SessionKey = req.SessionKey
            };
            var sessionResult = await _api.RequestApprovalSessionAsync(session, ct);
            if (sessionResult.Blocked)
                return new PipeResponse { Ok = true, RequestId = sessionResult.RequestId, RequestStatus = "blocked", Blocked = true, Message = sessionResult.DecisionNote ?? "This application is explicitly blocked by an administrator." };
            if (sessionResult.AlreadyApproved)
                return new PipeResponse { Ok = true, RequestId = sessionResult.RequestId, RequestStatus = "approved", AlreadyApproved = true, Message = $"All components are already approved by existing policy coverage." };
            if (sessionResult.Duplicate)
                return new PipeResponse { Ok = true, RequestId = sessionResult.RequestId, RequestStatus = sessionResult.Status, Duplicate = true, Message = $"Approval request {sessionResult.RequestId} already exists and is {FriendlyStatus(sessionResult.Status)}." };
            return new PipeResponse { Ok = sessionResult.Ok, RequestId = sessionResult.RequestId, RequestStatus = sessionResult.Status ?? "pending", Message = $"Approval request {sessionResult.RequestId} submitted for {components.Count} related component(s)." };
        }

        var isUserBlock = string.Equals(req.Action, "block", StringComparison.OrdinalIgnoreCase);
        var isInstallation = string.Equals(req.Action, "request_installation", StringComparison.OrdinalIgnoreCase);
        if (!isUserBlock && !isInstallation && !string.Equals(req.Action, "request", StringComparison.OrdinalIgnoreCase))
            return new PipeResponse { Ok = false, Message = "Unknown local request action." };
        if (string.IsNullOrWhiteSpace(req.FilePath))
            return new PipeResponse { Ok = false, Message = "Select an application first." };

        var originalPath = DevicePathResolver.Resolve(req.FilePath) ?? req.FilePath;
        var approvalSnapshot = req.RecordId.HasValue ? _cache.Get(req.RecordId.Value) : null;
        if (isUserBlock && approvalSnapshot is null)
            return new PipeResponse { Ok = false, Message = "User-created blocks are only available for an application that Windows App Control just blocked." };
        var sourcePath = File.Exists(originalPath)
            ? originalPath
            : (approvalSnapshot?.CachedPath is not null && File.Exists(approvalSnapshot.CachedPath) ? approvalSnapshot.CachedPath : null);

        if (sourcePath is null)
            return new PipeResponse
            {
                Ok = false,
                Message = "This temporary component disappeared before AppControl Manager could preserve it. Re-run the original application or installer and request access again."
            };

        var meta = FileMetadataReader.Read(sourcePath);
        var apiReq = new ApprovalRequest
        {
            FilePath = originalPath,
            PolicySourcePath = string.Equals(sourcePath, originalPath, StringComparison.OrdinalIgnoreCase) ? null : sourcePath,
            Sha256 = meta.Sha256 ?? approvalSnapshot?.Sha256,
            Publisher = meta.Publisher ?? approvalSnapshot?.Publisher,
            ProductName = meta.ProductName ?? approvalSnapshot?.ProductName,
            FileVersion = meta.FileVersion ?? approvalSnapshot?.FileVersion,
            Reason = req.Reason,
            RequestedBy = req.RequestedBy
        };
        if (isUserBlock)
        {
            var blockResult = await _api.RequestUserBlockAsync(apiReq, ct);
            return new PipeResponse
            {
                Ok = blockResult.Ok,
                Blocked = true,
                Disposition = blockResult.State,
                DecisionNote = blockResult.DecisionNote,
                Message = blockResult.DecisionNote ?? "Blocked on this device."
            };
        }

        if (isInstallation)
        {
            var install = await _api.RequestInstallationAsync(apiReq, ct);
            return new PipeResponse { Ok=install.Ok, InstallationId=install.InstallationId, RequestStatus=install.Status, Duplicate=install.Duplicate, Message=install.Duplicate ? $"Installation request {install.InstallationId} already exists and is {install.Status}." : $"Installation request {install.InstallationId} submitted." };
        }

        var r = await _api.RequestApprovalAsync(apiReq, ct);
        if (r.Blocked)
            return new PipeResponse { Ok = true, RequestId = r.RequestId, RequestStatus = "blocked", Blocked = true, Message = r.DecisionNote ?? "This application is explicitly blocked by an administrator." };
        if (r.AlreadyApproved)
            return new PipeResponse { Ok = true, RequestId = r.RequestId, RequestStatus = "approved", AlreadyApproved = true, Message = $"Already approved by policy {r.PolicyId} ({r.RuleType})." };
        if (r.Duplicate)
            return new PipeResponse { Ok = true, RequestId = r.RequestId, RequestStatus = r.Status, Duplicate = true, Message = $"Approval request {r.RequestId} already exists and is {FriendlyStatus(r.Status)}." };
        return new PipeResponse { Ok = r.Ok, RequestId = r.RequestId, RequestStatus = r.Status ?? "pending", Message = $"Approval request {r.RequestId} submitted." };
    }

    private static bool IsActive(ApprovalStatusInfo r) => r.Status is "pending" or "approving";

    private static string FriendlyStatus(string? status) => status switch
    {
        "pending" => "Pending",
        "approving" => "Approving",
        "approved" => "Approved",
        "approved_existing" => "Approved",
        "denied" => "Denied",
        "approval_failed" => "Failed",
        "blocked" => "Blocked by administrator",
        "revoked" => "Approval revoked",
        _ => status ?? "Unknown"
    };

    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(AppGuardPaths.PipeName, PipeDirection.InOut, 4,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
    }
}
