using AppGuard.Core;

internal static class WorkerPolicyValidationBehavior
{
    private const string Sha1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string Sha256 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string SignerRoot = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    private static readonly WorkerPolicyInputIdentity Expected = new(
        fileName: "Contoso.exe",
        originalFileName: "Contoso.exe",
        internalName: "Contoso",
        productName: "Contoso App",
        fileVersion: "1.2.3.4",
        contentSha256: Sha256,
        expectedPolicyHashes: new[] { Sha1, Sha256 },
        publisherNames: new[] { "Contoso Software" },
        signerTbsHashes: new[] { SignerRoot });

    public static void Run()
    {
        Rejects("mutation: unrelated hash is accepted", UnrelatedHashPolicy, "primary_allow");
        Rejects("mutation: unrelated ProductName is accepted", UnrelatedProductPolicy, "primary_allow");
        Rejects("mutation: unrelated signer is accepted", UnrelatedSignerPolicy, "primary_allow");
        Accepts("exact hash identity", ExactHashPolicy, "primary_allow", "hash");
        RemovesUntrustedPageHashes();
        Accepts("exact ProductName and signer identity", ExactProductPolicy, "primary_allow", "product");
        Accepts("exact FilePublisher file/version and signer identity", ExactFilePublisherPolicy, "primary_allow", "filepublisher");
        Accepts("exact deny hash identity", ExactDenyHashPolicy, "deny_policy", "hash");
        Rejects("mutation: allow operation accepts deny semantics", ExactDenyHashPolicy, "primary_allow");
        Rejects("mutation: deny operation accepts allow semantics", ExactHashPolicy, "deny_policy");
        Rejects("mutation: malformed policy is accepted", MalformedPolicy, "primary_allow");
    }

    private static void Accepts(string name, string xml, string operation, string mode)
    {
        var path = WriteFixture(xml);
        try
        {
            var actualMode = WorkerPolicyValidator.ValidateAndNormalizeFile(path, operation, Expected);
            if (!actualMode.Equals(mode, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"{name} derived unexpected rule mode {actualMode}.");
        }
        catch (Exception ex) { throw new InvalidOperationException($"{name} unexpectedly failed: {ex.Message}", ex); }
        finally { File.Delete(path); }
    }

    private static void Rejects(string name, string xml, string operation)
    {
        var path = WriteFixture(xml);
        try
        {
            WorkerPolicyValidator.ValidateAndNormalizeFile(path, operation, Expected);
            throw new InvalidOperationException(name);
        }
        catch (InvalidDataException) { }
        finally { File.Delete(path); }
    }

    private static string WriteFixture(string xml)
    {
        var path = Path.Combine(Path.GetTempPath(), $"acm-worker-policy-{Guid.NewGuid():N}.xml");
        File.WriteAllText(path, xml);
        return path;
    }

    private static void RemovesUntrustedPageHashes()
    {
        var path = WriteFixture(HashPolicyWithUntrustedPageRules);
        try
        {
            WorkerPolicyValidator.ValidateAndNormalizeFile(path, "primary_allow", Expected);
            if (File.ReadAllText(path).Contains("Hash Page", StringComparison.Ordinal))
                throw new InvalidOperationException("mutation: unvalidated page hash remains publishable");
        }
        finally { File.Delete(path); }
    }

    private const string ExactHashPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{11111111-1111-1111-1111-111111111111}</BasePolicyID><PolicyID>{11111111-1111-1111-1111-111111111111}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules>
            <Allow ID="ID_ALLOW_SHA1" FriendlyName="Contoso.exe Hash Sha1" Hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"/>
            <Allow ID="ID_ALLOW_SHA256" FriendlyName="Contoso.exe Hash Sha256" Hash="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"/>
          </FileRules><Signers/>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_ALLOW_SHA1"/><FileRuleRef RuleID="ID_ALLOW_SHA256"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string UnrelatedHashPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{11111111-1111-1111-1111-111111111111}</BasePolicyID><PolicyID>{11111111-1111-1111-1111-111111111111}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules>
            <Allow ID="ID_ALLOW_SHA1" FriendlyName="Other.exe Hash Sha1" Hash="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"/>
            <Allow ID="ID_ALLOW_SHA256" FriendlyName="Other.exe Hash Sha256" Hash="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"/>
          </FileRules><Signers/>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_ALLOW_SHA1"/><FileRuleRef RuleID="ID_ALLOW_SHA256"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string HashPolicyWithUntrustedPageRules = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{11111111-1111-1111-1111-111111111111}</BasePolicyID><PolicyID>{11111111-1111-1111-1111-111111111111}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules>
            <Allow ID="ID_ALLOW_SHA1" FriendlyName="Contoso.exe Hash Sha1" Hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"/>
            <Allow ID="ID_ALLOW_SHA256" FriendlyName="Contoso.exe Hash Sha256" Hash="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"/>
            <Allow ID="ID_ALLOW_PAGE_SHA1" FriendlyName="Other.exe Hash Page Sha1" Hash="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"/>
            <Allow ID="ID_ALLOW_PAGE_SHA256" FriendlyName="Other.exe Hash Page Sha256" Hash="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"/>
          </FileRules><Signers/>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_ALLOW_SHA1"/><FileRuleRef RuleID="ID_ALLOW_SHA256"/><FileRuleRef RuleID="ID_ALLOW_PAGE_SHA1"/><FileRuleRef RuleID="ID_ALLOW_PAGE_SHA256"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string ExactProductPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{22222222-2222-2222-2222-222222222222}</BasePolicyID><PolicyID>{22222222-2222-2222-2222-222222222222}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules><FileAttrib ID="ID_FILEATTRIB_PRODUCT" ProductName="Contoso App" MinimumFileVersion="1.2.3.4"/></FileRules>
          <Signers><Signer ID="ID_SIGNER_CONTOSO"><CertRoot Type="TBS" Value="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"/><CertPublisher Value="Contoso Software"/><FileAttribRef RuleID="ID_FILEATTRIB_PRODUCT"/></Signer></Signers>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_CONTOSO"/></AllowedSigners></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners><CiSigner SignerId="ID_SIGNER_CONTOSO"/></CiSigners><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string UnrelatedProductPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{22222222-2222-2222-2222-222222222222}</BasePolicyID><PolicyID>{22222222-2222-2222-2222-222222222222}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules><FileAttrib ID="ID_FILEATTRIB_PRODUCT" ProductName="Unrelated App" MinimumFileVersion="1.2.3.4"/></FileRules>
          <Signers><Signer ID="ID_SIGNER_CONTOSO"><CertRoot Type="TBS" Value="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"/><CertPublisher Value="Contoso Software"/><FileAttribRef RuleID="ID_FILEATTRIB_PRODUCT"/></Signer></Signers>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_CONTOSO"/></AllowedSigners></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners><CiSigner SignerId="ID_SIGNER_CONTOSO"/></CiSigners><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string UnrelatedSignerPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{22222222-2222-2222-2222-222222222222}</BasePolicyID><PolicyID>{22222222-2222-2222-2222-222222222222}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules><FileAttrib ID="ID_FILEATTRIB_PRODUCT" ProductName="Contoso App" MinimumFileVersion="1.2.3.4"/></FileRules>
          <Signers><Signer ID="ID_SIGNER_OTHER"><CertRoot Type="TBS" Value="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"/><CertPublisher Value="Unrelated Software"/><FileAttribRef RuleID="ID_FILEATTRIB_PRODUCT"/></Signer></Signers>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_OTHER"/></AllowedSigners></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners><CiSigner SignerId="ID_SIGNER_OTHER"/></CiSigners><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string ExactFilePublisherPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{33333333-3333-3333-3333-333333333333}</BasePolicyID><PolicyID>{33333333-3333-3333-3333-333333333333}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules><FileAttrib ID="ID_FILEATTRIB_FILE" FileName="Contoso.exe" MinimumFileVersion="1.2.3.4"/></FileRules>
          <Signers><Signer ID="ID_SIGNER_CONTOSO"><CertRoot Type="TBS" Value="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"/><CertPublisher Value="Contoso Software"/><FileAttribRef RuleID="ID_FILEATTRIB_FILE"/></Signer></Signers>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_CONTOSO"/></AllowedSigners></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners><CiSigner SignerId="ID_SIGNER_CONTOSO"/></CiSigners><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string ExactDenyHashPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
          <VersionEx>10.0.0.0</VersionEx><BasePolicyID>{44444444-4444-4444-4444-444444444444}</BasePolicyID><PolicyID>{44444444-4444-4444-4444-444444444444}</PolicyID>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules><Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule></Rules>
          <EKUs/><FileRules>
            <Deny ID="ID_DENY_SHA1" FriendlyName="Contoso.exe Hash Sha1" Hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"/>
            <Deny ID="ID_DENY_SHA256" FriendlyName="Contoso.exe Hash Sha256" Hash="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"/>
          </FileRules><Signers/>
          <SigningScenarios><SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS"><ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_DENY_SHA1"/><FileRuleRef RuleID="ID_DENY_SHA256"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
          <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
        </SiPolicy>
        """;

    private const string MalformedPolicy = """
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy"><Rules>
        """;
}
