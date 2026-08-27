using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AppGuard.Core;

namespace AppGuard.Service;

internal sealed class CommandReceiptStore
{
    private const int MaxReceipts = 100;
    private static readonly string ReceiptPath = Path.Combine(AppGuardPaths.ProgramDataRoot, "command-receipts.json");
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    private readonly object _sync = new();

    internal sealed class Receipt
    {
        public string DeviceId { get; set; } = "";
        public long CommandId { get; set; }
        public string CommandType { get; set; } = "";
        public string PayloadFingerprint { get; set; } = "";
        public CommandComplete Completion { get; set; } = new();
        public DateTimeOffset RecordedAt { get; set; } = DateTimeOffset.UtcNow;
    }

    public static string Fingerprint(AgentCommand command)
    {
        var payload = JsonSerializer.Serialize(command.Payload);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(command.CommandType + "\n" + payload));
        return Convert.ToHexString(bytes);
    }

    public Receipt? Find(string deviceId, AgentCommand command)
    {
        lock (_sync)
        {
            var fp = Fingerprint(command);
            return Read().FirstOrDefault(r => r.DeviceId == deviceId && r.CommandId == command.Id &&
                r.CommandType == command.CommandType && r.PayloadFingerprint == fp);
        }
    }

    public void Save(string deviceId, AgentCommand command, CommandComplete completion)
    {
        lock (_sync)
        {
            Directory.CreateDirectory(AppGuardPaths.ProgramDataRoot);
            var rows = Read();
            rows.RemoveAll(r => r.DeviceId == deviceId && r.CommandId == command.Id);
            rows.Insert(0, new Receipt
            {
                DeviceId = deviceId, CommandId = command.Id, CommandType = command.CommandType,
                PayloadFingerprint = Fingerprint(command), Completion = completion, RecordedAt = DateTimeOffset.UtcNow
            });
            if (rows.Count > MaxReceipts) rows.RemoveRange(MaxReceipts, rows.Count - MaxReceipts);
            var temp = ReceiptPath + ".tmp." + Environment.ProcessId;
            File.WriteAllText(temp, JsonSerializer.Serialize(rows, JsonOptions));
            File.Move(temp, ReceiptPath, true);
        }
    }

    private static List<Receipt> Read()
    {
        try
        {
            if (!File.Exists(ReceiptPath)) return [];
            return JsonSerializer.Deserialize<List<Receipt>>(File.ReadAllText(ReceiptPath), JsonOptions) ?? [];
        }
        catch { return []; }
    }
}
