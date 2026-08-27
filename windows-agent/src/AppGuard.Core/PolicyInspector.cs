using System.Xml.Linq;

namespace AppGuard.Core;

public static class PolicyInspector
{
    private static readonly XNamespace Ns = "urn:schemas-microsoft-com:sipolicy";

    public static string GetMode()
    {
        if (!File.Exists(AppGuardPaths.BasePolicyXml)) return "unknown";
        var doc = XDocument.Load(AppGuardPaths.BasePolicyXml);
        return HasOption(doc, "Enabled:Audit Mode") ? "learning" : "enforcement";
    }

    public static bool? IsScriptEnforcementDisabled()
    {
        if (!File.Exists(AppGuardPaths.BasePolicyXml)) return null;
        var doc = XDocument.Load(AppGuardPaths.BasePolicyXml);
        return HasOption(doc, "Disabled:Script Enforcement");
    }

    private static bool HasOption(XDocument doc, string value) =>
        doc.Descendants(Ns + "Option").Any(x => string.Equals(x.Value.Trim(), value, StringComparison.OrdinalIgnoreCase));
}
