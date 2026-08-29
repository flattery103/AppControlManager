using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using AppGuard.Core;

namespace AppGuard.Service;

public sealed class EventCollector
{
    private const string LogName = "Microsoft-Windows-CodeIntegrity/Operational";

    public List<EventUpload> ReadAfter(long afterRecordId, int max = 200)
    {
        var xpath = $"*[System[((EventID=3076) or (EventID=3077)) and EventRecordID > {afterRecordId}]]";
        var query = new EventLogQuery(LogName, PathType.LogName, xpath) { ReverseDirection = false };
        using var reader = new EventLogReader(query);
        var results = new List<EventUpload>();
        for (EventRecord? record = reader.ReadEvent(); record is not null && results.Count < max; record = reader.ReadEvent())
        {
            using (record)
            {
                results.Add(FromRecord(record));
            }
        }
        return results.OrderBy(x => x.RecordId).ToList();
    }

    public static EventUpload FromRecord(EventRecord record)
    {
        var data = ParseData(record.ToXml());
        var path = DevicePathResolver.Resolve(First(data, "File Name", "FileName"));
        var parent = DevicePathResolver.Resolve(First(data, "Process Name", "ProcessName"));
        var meta = !string.IsNullOrWhiteSpace(path) ? FileMetadataReader.Read(path) : null;
        return new EventUpload
        {
            EventId = record.Id,
            RecordId = record.RecordId,
            OccurredAt = record.TimeCreated?.ToUniversalTime().ToString("O"),
            FilePath = path,
            ParentPath = parent,
            Sha256 = meta?.Sha256,
            Publisher = meta?.Publisher,
            ProductName = meta?.ProductName,
            FileVersion = meta?.FileVersion,
            Raw = new Dictionary<string,string?>
            {
                ["policy_id"] = First(data, "Policy ID", "PolicyID"),
                ["policy_name"] = First(data, "Policy Name", "PolicyName"),
                ["requested_signing_level"] = First(data, "Requested Signing Level", "RequestedSigningLevel")
            }
        };
    }

    public static string? LatestBlockedFile()
    {
        var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=3077)]]") { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent();
        if (record is null) return null;
        var data = ParseData(record.ToXml());
        var raw = First(data, "File Name", "FileName");
        return DevicePathResolver.Resolve(raw);
    }

    private static Dictionary<string,string?> ParseData(string xml)
    {
        var doc = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        return doc.Descendants(ns + "Data")
            .Where(x => x.Attribute("Name") is not null)
            .GroupBy(x => (string)x.Attribute("Name")!)
            .ToDictionary(g => g.Key, g => (string?)g.First());
    }

    private static string? First(Dictionary<string,string?> data, params string[] names)
    {
        foreach (var name in names)
            if (data.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)) return value;
        return null;
    }
}
