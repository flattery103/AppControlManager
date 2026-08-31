using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace AppGuard.Core;

public static class WorkerPolicyValidator
{
    private static readonly HashSet<string> AllowedWorkerRuleOptions = new(StringComparer.Ordinal)
    {
        "Enabled:UMCI",
        "Enabled:Audit Mode",
        "Enabled:Unsigned System Integrity Policy",
        "Enabled:Advanced Boot Options Menu",
        // ConfigCI adds this restrictive host option on current Windows builds. It does
        // not grant file execution and is safe to retain in generation-only output.
        "Required:Enforce Store Applications"
    };

    public static string ValidateAndNormalizeFile(
        string path,
        string operation,
        WorkerPolicyInputIdentity expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var document = LoadPolicy(path);
        RemovePageHashRules(document);
        var validatedRuleMode = ValidateOperationSemantics(operation, document, expected);

        var temp = path + ".validated." + Guid.NewGuid().ToString("N");
        try
        {
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false),
                Indent = false,
                OmitXmlDeclaration = false
            };
            using (var writer = XmlWriter.Create(temp, settings)) document.Save(writer);
            File.Move(temp, path, true);
        }
        finally { try { File.Delete(temp); } catch { } }
        return validatedRuleMode;
    }

    private static XDocument LoadPolicy(string path)
    {
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = WorkerOutputSnapshot.MaximumPolicyBytes
            };
            using var reader = XmlReader.Create(path, settings);
            var document = XDocument.Load(reader, LoadOptions.None);
            if (document.Root is null ||
                !document.Root.Name.LocalName.Equals("SiPolicy", StringComparison.Ordinal) ||
                !document.Root.Name.NamespaceName.Equals("urn:schemas-microsoft-com:sipolicy", StringComparison.Ordinal))
                throw new InvalidDataException("Rule worker output was not a Windows App Control policy.");
            return document;
        }
        catch (Exception ex) when (ex is IOException or XmlException)
        {
            throw new InvalidDataException("Rule worker produced invalid policy XML.", ex);
        }
    }

    private static void RemovePageHashRules(XDocument document)
    {
        XNamespace ns = "urn:schemas-microsoft-com:sipolicy";
        var pageRules = document.Descendants()
            .Where(x => x.Name == ns + "Allow" || x.Name == ns + "Deny")
            .Where(x => IsPageHashName(x.Attribute("FriendlyName")?.Value))
            .ToArray();
        var ids = new HashSet<string>(
            pageRules.Select(x => x.Attribute("ID")?.Value).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!),
            StringComparer.OrdinalIgnoreCase);
        foreach (var reference in document.Descendants(ns + "FileRuleRef")
                     .Where(x => ids.Contains(x.Attribute("RuleID")?.Value ?? "")).ToArray())
            reference.Remove();
        foreach (var pageRule in pageRules) pageRule.Remove();
    }

    private static bool IsPageHashName(string? value)
        => value?.EndsWith(" Hash Page Sha1", StringComparison.OrdinalIgnoreCase) == true ||
           value?.EndsWith(" Hash Page Sha256", StringComparison.OrdinalIgnoreCase) == true;

    private static string ValidateOperationSemantics(
        string operation,
        XDocument document,
        WorkerPolicyInputIdentity expected)
    {
        XNamespace ns = "urn:schemas-microsoft-com:sipolicy";
        var root = document.Root!;
        if (!string.Equals(root.Attribute("PolicyType")?.Value, "Base Policy", StringComparison.Ordinal))
            throw new InvalidDataException("Worker policy must have an unprocessed base policy identity.");
        var policyIds = root.Elements(ns + "PolicyID").ToArray();
        var basePolicyIds = root.Elements(ns + "BasePolicyID").ToArray();
        if (policyIds.Length != 1 || basePolicyIds.Length != 1 ||
            !Guid.TryParse(policyIds[0].Value, out var policyId) ||
            !Guid.TryParse(basePolicyIds[0].Value, out var basePolicyId))
            throw new InvalidDataException("Worker policy identity is missing or invalid.");
        if (policyId != basePolicyId)
            throw new InvalidDataException("Worker PolicyID and BasePolicyID must match before LocalSystem post-processing.");
        var platformIds = root.Elements(ns + "PlatformID").ToArray();
        if (platformIds.Length != 1 ||
            !platformIds[0].Value.Equals("{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Unexpected policy content: worker policy platform is invalid.");
        var hvciOptions = root.Elements(ns + "HvciOptions").ToArray();
        if (hvciOptions.Length != 1 || !hvciOptions[0].Value.Trim().Equals("0", StringComparison.Ordinal))
            throw new InvalidDataException("Unexpected policy content: worker policy HVCI options are invalid.");
        var prohibitedContent = new[]
        {
            "UpdatePolicySigner", "SupplementalPolicySigner", "TestSigner",
            "TestSigningSigner", "AppIDTag", "Macro", "ExceptDenyRule", "ExceptAllowRule"
        };
        if (prohibitedContent.Any(name => document.Descendants(ns + name).Any()))
            throw new InvalidDataException("Unexpected policy content in worker-generated policy.");

        foreach (var optionElement in document.Descendants(ns + "Option"))
        {
            if (optionElement.Parent?.Name != ns + "Rule" || optionElement.Parent.Parent?.Name != ns + "Rules")
                throw new InvalidDataException("Unexpected policy content: rule option is outside the Rules section.");
            var option = optionElement.Value.Trim();
            if (!AllowedWorkerRuleOptions.Contains(option))
                throw new InvalidDataException("Unexpected rule option in worker policy: " + option);
        }

        var signingScenarios = document.Descendants(ns + "SigningScenario").ToArray();
        if (signingScenarios.Length == 0 ||
            signingScenarios.Any(x => x.Attribute("Value")?.Value is not ("12" or "131")))
            throw new InvalidDataException("Unexpected policy content: worker policy has an unsupported signing scenario.");

        var allowRules = document.Descendants(ns + "Allow").ToArray();
        var allowedSigners = document.Descendants(ns + "AllowedSigner").ToArray();
        var denyRules = document.Descendants(ns + "Deny").ToArray();
        var deniedSigners = document.Descendants(ns + "DeniedSigner").ToArray();
        var fileAttributes = document.Descendants(ns + "FileAttrib").ToArray();
        if (allowRules.Length + allowedSigners.Length + denyRules.Length + deniedSigners.Length is 0 or > 16)
            throw new InvalidDataException("Worker policy contains an invalid number of authorization rules.");

        if (string.IsNullOrWhiteSpace(operation))
            throw new InvalidDataException("Worker policy operation is not recognized.");
        var normalizedOperation = operation.ToLowerInvariant();
        var isAllowOperation = normalizedOperation is "product" or "hash" or "primary_allow";
        if (isAllowOperation)
        {
            if (denyRules.Length != 0 || deniedSigners.Length != 0)
                throw new InvalidDataException("Allow generation contained deny semantics.");
            var validatedRuleMode = DeriveRuleMode(allowRules, allowedSigners, fileAttributes, deny: false);
            if (normalizedOperation == "product" && !validatedRuleMode.Equals("product", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Product generation returned an unexpected rule mode.");
            if (normalizedOperation == "hash" && !validatedRuleMode.Equals("hash", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Hash generation returned an unexpected rule mode.");
            ValidateRuleMode(validatedRuleMode, allowRules, allowedSigners, fileAttributes, document, ns, expected, deny: false);
            return validatedRuleMode;
        }

        if (normalizedOperation != "deny_policy")
            throw new InvalidDataException("Worker policy operation is not recognized.");
        if (allowRules.Length != 0 || allowedSigners.Length != 0)
            throw new InvalidDataException("Deny generation contained allow semantics.");
        var validatedDenyRuleMode = DeriveRuleMode(denyRules, deniedSigners, fileAttributes, deny: true);
        ValidateRuleMode(validatedDenyRuleMode, denyRules, deniedSigners, fileAttributes, document, ns, expected, deny: true);
        return validatedDenyRuleMode;
    }

    private static string DeriveRuleMode(
        IReadOnlyCollection<XElement> hashRules,
        IReadOnlyCollection<XElement> signerReferences,
        IReadOnlyCollection<XElement> fileAttributes,
        bool deny)
    {
        if (hashRules.Count > 0)
        {
            if (signerReferences.Count != 0 || fileAttributes.Count != 0)
                throw new InvalidDataException("Worker policy mixed hash and publisher semantics.");
            return "hash";
        }
        if (signerReferences.Count == 0 || fileAttributes.Count == 0)
            throw new InvalidDataException("Worker policy did not contain a complete authorization rule.");

        var productScoped = fileAttributes.All(x =>
            !string.IsNullOrWhiteSpace(x.Attribute("ProductName")?.Value) &&
            new[] { "FileName", "OriginalFileName", "InternalName" }
                .All(name => string.IsNullOrWhiteSpace(x.Attribute(name)?.Value)));
        if (productScoped) return deny ? "product_family" : "product";

        var fileScoped = fileAttributes.All(x =>
            string.IsNullOrWhiteSpace(x.Attribute("ProductName")?.Value) &&
            new[] { "FileName", "OriginalFileName", "InternalName" }
                .Count(name => !string.IsNullOrWhiteSpace(x.Attribute(name)?.Value)) == 1);
        if (fileScoped) return "filepublisher";
        throw new InvalidDataException("Worker policy mixed or omitted publisher scope semantics.");
    }

    private static void ValidateRuleMode(
        string ruleMode,
        XElement[] hashRules,
        XElement[] signerReferences,
        XElement[] fileAttributes,
        XDocument document,
        XNamespace ns,
        WorkerPolicyInputIdentity expected,
        bool deny)
    {
        if (ruleMode.Equals("hash", StringComparison.OrdinalIgnoreCase))
        {
            if (signerReferences.Length != 0 || hashRules.Length == 0 ||
                !AllHashRulesMatchExpectedInput(hashRules, document, ns, expected))
                throw new InvalidDataException($"Hash {(deny ? "deny" : "allow")} generation did not match the staged input.");
            return;
        }

        var productMode = ruleMode.Equals(deny ? "product_family" : "product", StringComparison.OrdinalIgnoreCase);
        var filePublisherMode = ruleMode.Equals("filepublisher", StringComparison.OrdinalIgnoreCase);
        if (!productMode && !filePublisherMode)
            throw new InvalidDataException($"{(deny ? "Deny" : "Allow")} generation returned an unexpected rule mode.");
        signerReferences = RemoveUnvalidatedCompanionSigners(
            signerReferences, document, ns, expected);
        if (hashRules.Length != 0 || signerReferences.Length == 0 || fileAttributes.Length == 0 ||
            !AllSignerRulesMatchExpectedInput(signerReferences, fileAttributes, document, ns, expected, productMode))
            throw new InvalidDataException($"FilePublisher {(deny ? "deny" : "allow")} generation did not match the staged input.");
    }

    private static XElement[] RemoveUnvalidatedCompanionSigners(
        XElement[] signerReferences,
        XDocument document,
        XNamespace ns,
        WorkerPolicyInputIdentity expected)
    {
        var referencedIds = new HashSet<string>(
            signerReferences
                .Select(reference => reference.Attribute("SignerId")?.Value)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!),
            StringComparer.OrdinalIgnoreCase);
        var validatedSignerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var signer in document.Descendants(ns + "Signer").ToArray())
        {
            var signerId = signer.Attribute("ID")?.Value;
            var roots = signer.Descendants(ns + "CertRoot").ToArray();
            var publishers = signer.Descendants(ns + "CertPublisher").ToArray();
            var validatesStagedSigner = !string.IsNullOrWhiteSpace(signerId) &&
                referencedIds.Contains(signerId) &&
                roots.Length > 0 && publishers.Length > 0 &&
                roots.All(root =>
                    root.Attribute("Type")?.Value.Equals("TBS", StringComparison.OrdinalIgnoreCase) == true &&
                    expected.SignerTbsHashes.Contains(root.Attribute("Value")?.Value ?? "")) &&
                publishers.All(publisher =>
                    expected.PublisherNames.Contains(publisher.Attribute("Value")?.Value ?? ""));
            if (validatesStagedSigner)
            {
                validatedSignerIds.Add(signerId!);
                continue;
            }

            if (!string.IsNullOrWhiteSpace(signerId))
            {
                foreach (var signerReference in document.Descendants()
                             .Where(element =>
                                 element.Attribute("SignerId")?.Value.Equals(
                                     signerId, StringComparison.OrdinalIgnoreCase) == true)
                             .ToArray())
                    signerReference.Remove();
            }
            signer.Remove();
        }

        return signerReferences
            .Where(reference => reference.Parent is not null &&
                validatedSignerIds.Contains(reference.Attribute("SignerId")?.Value ?? ""))
            .ToArray();
    }

    private static bool AllHashRulesMatchExpectedInput(
        IEnumerable<XElement> hashRules,
        XDocument document,
        XNamespace ns,
        WorkerPolicyInputIdentity expected)
    {
        if (document.Descendants(ns + "Signer").Any() || document.Descendants(ns + "FileAttrib").Any() ||
            document.Descendants(ns + "CiSigner").Any())
            return false;
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sawSha1 = false;
        var sawSha256 = false;
        foreach (var rule in hashRules)
        {
            var id = rule.Attribute("ID")?.Value;
            var hash = rule.Attribute("Hash")?.Value?.Trim();
            var friendlyName = rule.Attribute("FriendlyName")?.Value;
            if (string.IsNullOrWhiteSpace(id) || !ids.Add(id) || string.IsNullOrWhiteSpace(hash) ||
                !expected.ExpectedPolicyHashes.Contains(hash))
                return false;
            if (friendlyName?.EndsWith(" Hash Sha1", StringComparison.OrdinalIgnoreCase) == true && hash.Length == 40)
                sawSha1 = true;
            else if (friendlyName?.EndsWith(" Hash Sha256", StringComparison.OrdinalIgnoreCase) == true && hash.Length == 64)
                sawSha256 = true;
            else return false;
        }
        var references = document.Descendants(ns + "FileRuleRef")
            .Select(x => x.Attribute("RuleID")?.Value)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .ToArray();
        return sawSha1 && sawSha256 && references.Length > 0 &&
               references.All(ids.Contains) && ids.All(id => references.Contains(id, StringComparer.OrdinalIgnoreCase));
    }

    private static bool AllSignerRulesMatchExpectedInput(
        IEnumerable<XElement> signerReferences,
        IEnumerable<XElement> fileAttributes,
        XDocument document,
        XNamespace ns,
        WorkerPolicyInputIdentity expected,
        bool productMode)
    {
        if (expected.PublisherNames.Count == 0 || expected.SignerTbsHashes.Count == 0 || expected.FileVersion is null ||
            (productMode && expected.ProductName is null))
            return false;
        if (document.Descendants(ns + "FileRuleRef").Any()) return false;

        var fileAttributeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fileAttribute in fileAttributes)
        {
            var id = fileAttribute.Attribute("ID")?.Value;
            if (string.IsNullOrWhiteSpace(id) || !fileAttributeIds.Add(id) ||
                !expected.MatchesVersion(fileAttribute.Attribute("MinimumFileVersion")?.Value))
                return false;
            if (productMode)
            {
                if (!string.Equals(fileAttribute.Attribute("ProductName")?.Value, expected.ProductName, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            else
            {
                var scopedName = new[] { "FileName", "OriginalFileName", "InternalName" }
                    .Select(name => fileAttribute.Attribute(name)?.Value)
                    .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
                if (!expected.MatchesFileName(scopedName)) return false;
            }
        }

        var signers = new Dictionary<string, XElement>(StringComparer.OrdinalIgnoreCase);
        foreach (var signer in document.Descendants(ns + "Signer"))
        {
            var id = signer.Attribute("ID")?.Value;
            if (string.IsNullOrWhiteSpace(id) || !signers.TryAdd(id, signer)) return false;
        }
        var referencedSignerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var referencedFileAttributeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var signerReference in signerReferences)
        {
            var signerId = signerReference.Attribute("SignerId")?.Value;
            if (string.IsNullOrWhiteSpace(signerId) || !signers.TryGetValue(signerId, out var signer)) return false;
            referencedSignerIds.Add(signerId);
            var roots = signer.Descendants(ns + "CertRoot").ToArray();
            var publishers = signer.Descendants(ns + "CertPublisher").ToArray();
            if (roots.Length == 0 || publishers.Length == 0 ||
                roots.Any(x => !string.Equals(x.Attribute("Type")?.Value, "TBS", StringComparison.OrdinalIgnoreCase) ||
                               !expected.SignerTbsHashes.Contains(x.Attribute("Value")?.Value ?? "")) ||
                publishers.Any(x => !expected.PublisherNames.Contains(x.Attribute("Value")?.Value ?? "")))
                return false;
            var fileAttributeReferences = signer.Descendants(ns + "FileAttribRef").ToArray();
            if (fileAttributeReferences.Length == 0) return false;
            foreach (var fileAttributeReference in fileAttributeReferences)
            {
                var ruleId = fileAttributeReference.Attribute("RuleID")?.Value;
                if (string.IsNullOrWhiteSpace(ruleId) || !fileAttributeIds.Contains(ruleId)) return false;
                referencedFileAttributeIds.Add(ruleId);
            }
        }
        var ciSignerIds = document.Descendants(ns + "CiSigner")
            .Select(x => x.Attribute("SignerId")?.Value).ToArray();
        if (ciSignerIds.Any(x => string.IsNullOrWhiteSpace(x) || !referencedSignerIds.Contains(x))) return false;
        return signers.Keys.All(referencedSignerIds.Contains) && fileAttributeIds.All(referencedFileAttributeIds.Contains);
    }
}
