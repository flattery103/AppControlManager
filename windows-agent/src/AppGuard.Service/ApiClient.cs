using System.Net.Http.Json;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class ApiClient
{
    private readonly JsonFileStore _store;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(15) };
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    public ApiClient(JsonFileStore store) => _store = store;

    private HttpRequestMessage Request(HttpMethod method, string path, object? body = null)
    {
        var cfg = _store.ReadConfig();
        var req = new HttpRequestMessage(method, cfg.ServerUrl.TrimEnd('/') + path);
        req.Headers.Add("X-Device-ID", cfg.DeviceId);
        req.Headers.Add("X-Device-Key", cfg.DeviceKey);
        if (body is not null) req.Content = JsonContent.Create(body);
        return req;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
    {
        var response = await _http.SendAsync(req, ct);
        if (!response.IsSuccessStatusCode)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException($"HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {text}");
        }
        return response;
    }

    public async Task HeartbeatAsync(HeartbeatRequest body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/heartbeat", body);
        using var _ = await SendAsync(req, ct);
    }

    public async Task UploadEventsAsync(IReadOnlyList<EventUpload> events, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/events", events);
        using var _ = await SendAsync(req, ct);
    }


    public async Task<ApplicationDispositionResponse> GetDispositionAsync(ApplicationDispositionRequest body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/disposition", body);
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<ApplicationDispositionResponse>(Json, ct) ?? new ApplicationDispositionResponse();
    }

    public async Task<ApprovalResponse> RequestApprovalAsync(ApprovalRequest body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/requests", body);
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<ApprovalResponse>(Json, ct) ?? new ApprovalResponse();
    }


    public async Task<ApplicationDispositionResponse> RequestUserBlockAsync(ApprovalRequest body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/blocks/user", body);
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<ApplicationDispositionResponse>(Json, ct) ?? new ApplicationDispositionResponse();
    }


    public async Task<ApprovalResponse> RequestApprovalSessionAsync(ApprovalSessionRequest body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/requests/session", body);
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<ApprovalResponse>(Json, ct) ?? new ApprovalResponse();
    }


    public async Task<List<ApprovalStatusInfo>> GetRequestsAsync(string? requestedBy, CancellationToken ct)
    {
        var path = "/api/requests";
        if (!string.IsNullOrWhiteSpace(requestedBy))
            path += "?requested_by=" + Uri.EscapeDataString(requestedBy);
        using var req = Request(HttpMethod.Get, path);
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<List<ApprovalStatusInfo>>(Json, ct) ?? [];
    }

    public async Task<List<AgentCommand>> GetCommandsAsync(CancellationToken ct)
    {
        using var req = Request(HttpMethod.Get, "/api/commands");
        using var response = await SendAsync(req, ct);
        return await response.Content.ReadFromJsonAsync<List<AgentCommand>>(Json, ct) ?? [];
    }

    public async Task ReportBackgroundPolicyAsync(BackgroundPolicyReport body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "/api/background-policies/report", body);
        using var _ = await SendAsync(req, ct);
    }

    public async Task CompleteCommandAsync(long id, CommandComplete body, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, $"/api/commands/{id}/complete", body);
        using var _ = await SendAsync(req, ct);
    }

    public async Task DownloadFileAsync(string path, string destination, CancellationToken ct)
    {
        using var req = Request(HttpMethod.Get, path);
        using var response = await SendAsync(req, ct);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        await using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
        await input.CopyToAsync(output, ct);
    }
}
