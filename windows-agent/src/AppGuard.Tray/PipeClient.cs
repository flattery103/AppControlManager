using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Tray;

public static class PipeClient
{
    public static async Task<PipeResponse> SendAsync(PipeRequest request, CancellationToken ct = default)
    {
        using var pipe = new NamedPipeClientStream(".", AppGuardPaths.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, ct);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        await writer.WriteLineAsync(JsonSerializer.Serialize(request));
        var line = await reader.ReadLineAsync(ct);
        return JsonSerializer.Deserialize<PipeResponse>(line ?? "{}", new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
               ?? new PipeResponse { Ok = false, Message = "No response from AppControl Manager service." };
    }
}
