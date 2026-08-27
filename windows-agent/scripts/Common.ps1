$ErrorActionPreference = 'Stop'
$script:Root = 'C:\ProgramData\AppControlManager'
$script:ConfigPath = Join-Path $script:Root 'config.json'
$script:PolicyDir = Join-Path $script:Root 'Policies'
$script:StatePath = Join-Path $script:Root 'state.json'
$script:StateMutexName = 'Global\AppControlManager-State-v1'

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This command must be run from an elevated PowerShell session.'
    }
}

function Ensure-Directories {
    New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
    New-Item -ItemType Directory -Path $script:PolicyDir -Force | Out-Null
}

function Read-Config {
    if (!(Test-Path $script:ConfigPath)) { throw "Agent is not enrolled. Missing $script:ConfigPath" }
    return Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
}

function New-DefaultState {
    return [pscustomobject]@{ learning_mode=$false; learning_started=$null; base_policy_id=$null; last_record_id=0; policy_version=1 }
}

function Invoke-WithStateLock([scriptblock]$ScriptBlock) {
    $created = $false
    $mutex = New-Object System.Threading.Mutex($false, $script:StateMutexName, [ref]$created)
    $locked = $false
    try {
        try {
            $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
        } catch [System.Threading.AbandonedMutexException] {
            $locked = $true
        }
        if (-not $locked) { throw 'Timed out waiting for the AppControl Manager state lock.' }
        return & $ScriptBlock
    } finally {
        if ($locked) { try { $mutex.ReleaseMutex() } catch {} }
        $mutex.Dispose()
    }
}

function Read-StateUnsafe {
    if (!(Test-Path $script:StatePath)) { return New-DefaultState }
    try {
        return Get-Content $script:StatePath -Raw | ConvertFrom-Json
    } catch {
        throw "Could not read AppControl Manager state file $script:StatePath : $($_.Exception.Message)"
    }
}

function Write-StateUnsafe($State) {
    Ensure-Directories
    $tmp = "$script:StatePath.tmp.$PID"
    try {
        $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $script:StatePath -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Read-State {
    return Invoke-WithStateLock { Read-StateUnsafe }
}

function Write-State($State) {
    Invoke-WithStateLock { Write-StateUnsafe $State } | Out-Null
}

function Update-State([hashtable]$Fields) {
    return Invoke-WithStateLock {
        $state = Read-StateUnsafe
        foreach ($key in $Fields.Keys) {
            $prop = $state.PSObject.Properties[$key]
            if ($null -ne $prop) { $prop.Value = $Fields[$key] }
            else { $state | Add-Member -NotePropertyName $key -NotePropertyValue $Fields[$key] }
        }
        Write-StateUnsafe $state
        return $state
    }
}

function Get-CIPolicyGuid([string]$XmlPath) {
    [xml]$x = Get-Content $XmlPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si','urn:schemas-microsoft-com:sipolicy')
    $node = $x.SelectSingleNode('/si:SiPolicy/si:PolicyID',$ns)
    if (!$node) { throw "Could not read PolicyID from $XmlPath" }
    return $node.InnerText.Trim('{}')
}

function Resolve-CIFilePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path -replace '^\\\\\?\\',''
    if ($p.StartsWith('\SystemRoot\', [System.StringComparison]::OrdinalIgnoreCase)) {
        return Join-Path $env:SystemRoot $p.Substring(12)
    }
    if ($p.StartsWith('\Device\HarddiskVolume', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not ('AppGuard.NativeMethods' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace AppGuard {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
    }
}
'@
        }
        foreach ($letter in [char[]](65..90)) {
            $drive = ([string]$letter) + ':'
            if (-not (Test-Path ($drive + '\'))) { continue }
            $sb = New-Object System.Text.StringBuilder 1024
            $n = [AppGuard.NativeMethods]::QueryDosDevice($drive, $sb, $sb.Capacity)
            if ($n -eq 0) { continue }
            $target = ($sb.ToString() -split "`0")[0]
            if ($p.StartsWith($target, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $drive + $p.Substring($target.Length)
            }
        }
    }
    return $p
}

function Get-FileMetadata([string]$Path) {
    $resolved = Resolve-CIFilePath $Path
    $o = [ordered]@{ file_path=$resolved; sha256=$null; publisher=$null; product_name=$null; file_version=$null }
    if (Test-Path -LiteralPath $resolved -PathType Leaf) {
        try { $o.sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash } catch {}
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $resolved
            if ($sig.SignerCertificate) { $o.publisher = $sig.SignerCertificate.Subject }
        } catch {}
        try {
            $v = (Get-Item -LiteralPath $resolved).VersionInfo
            $o.product_name = $v.ProductName
            $o.file_version = $v.FileVersion
        } catch {}
    }
    return [pscustomobject]$o
}

function Invoke-AgentApi([string]$Method, [string]$Path, $Body=$null) {
    $cfg = Read-Config
    $headers = @{ 'X-Device-ID'=$cfg.device_id; 'X-Device-Key'=$cfg.device_key }
    $uri = $cfg.server_url.TrimEnd('/') + $Path
    try {
        if ($null -eq $Body) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        }
        $json = ConvertTo-Json -InputObject $Body -Depth 12 -Compress
        # Windows PowerShell 5.1 can be inconsistent about string request-body
        # encoding. Send explicit UTF-8 bytes so FastAPI always receives valid JSON.
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $bytes = $utf8.GetBytes($json)
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes
    } catch {
        $msg = $_.Exception.Message
        $responseText = $null
        try {
            $resp = $_.Exception.Response
            if($null -ne $resp) {
                $stream = $resp.GetResponseStream()
                if($null -ne $stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseText = $reader.ReadToEnd()
                    $reader.Dispose()
                }
            }
        } catch {}
        if(-not [string]::IsNullOrWhiteSpace($responseText)) {
            throw "HTTP $Method $Path failed: $msg Response: $responseText"
        }
        throw "HTTP $Method $Path failed: $msg"
    }
}

function Test-PolicyAuditMode([string]$XmlPath) {
    if (!(Test-Path -LiteralPath $XmlPath)) { return $null }
    [xml]$x = Get-Content -LiteralPath $XmlPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si','urn:schemas-microsoft-com:sipolicy')
    $nodes = $x.SelectNodes('//si:Rules/si:Rule/si:Option',$ns)
    foreach($n in $nodes) {
        if ([string]$n.InnerText -eq 'Enabled:Audit Mode') { return $true }
    }
    return $false
}

function Test-PolicyScriptEnforcementDisabled([string]$XmlPath) {
    if (!(Test-Path -LiteralPath $XmlPath)) { return $null }
    [xml]$x = Get-Content -LiteralPath $XmlPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si','urn:schemas-microsoft-com:sipolicy')
    $nodes = $x.SelectNodes('//si:Rules/si:Rule/si:Option',$ns)
    foreach($n in $nodes) {
        if ([string]$n.InnerText -eq 'Disabled:Script Enforcement') { return $true }
    }
    return $false
}

function Get-CIEventData($Event) {
    [xml]$x = $Event.ToXml()
    $data = @{}
    foreach($d in $x.Event.EventData.Data) {
        $name = [string]$d.Name
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $data[$name] = [string]$d.'#text'
        }
    }
    return $data
}

function Get-CIEventValue([hashtable]$Data, [string[]]$Names) {
    foreach($name in $Names) {
        if($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$name])) {
            return [string]$Data[$name]
        }
    }
    return $null
}

function Get-AppGuardPolicyMode {
    $xml = Join-Path $script:PolicyDir 'BasePolicy.xml'
    $audit = Test-PolicyAuditMode $xml
    if ($null -eq $audit) { return 'unknown' }
    if ($audit) { return 'learning' }
    return 'enforcement'
}


function Test-AppGuardProtectedInstallPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $resolved = Resolve-CIFilePath $Path
    try { $resolved = [System.IO.Path]::GetFullPath($resolved) } catch { return $false }
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    foreach($root in $roots) {
        try { $fullRoot = [System.IO.Path]::GetFullPath($root).TrimEnd('\\') } catch { continue }
        if($resolved.StartsWith($fullRoot + '\\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-AppGuardProtectedPublisherBundleFiles([string]$PrimaryPath, [string]$Publisher, [int]$MaxDepth=4, [int]$MaxFiles=750) {
    $resolved = Resolve-CIFilePath $PrimaryPath
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return @() }
    if (-not (Test-AppGuardProtectedInstallPath $resolved)) { return @($resolved) }
    if ([string]::IsNullOrWhiteSpace($Publisher)) { return @($resolved) }

    $root = Split-Path -Parent $resolved
    # Many products place supporting binaries under a version-number subdirectory. If the
    # requested file is one of those children, scan from the application directory one level up.
    $leaf = Split-Path -Leaf $root
    if($leaf -match '^\d+(?:\.\d+){1,5}$') {
        $parent = Split-Path -Parent $root
        if(Test-AppGuardProtectedInstallPath $parent) { $root = $parent }
    }

    $extensions = @('.exe','.dll','.sys','.ocx','.cpl','.scr','.com')
    $result = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{ Path=$root; Depth=0 })

    while($queue.Count -gt 0 -and $result.Count -lt $MaxFiles) {
        $entry = $queue.Dequeue()
        $dir = [string]$entry.Path
        $depth = [int]$entry.Depth

        try {
            foreach($file in Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop) {
                if($result.Count -ge $MaxFiles) { break }
                if($extensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
                $candidate = $file.FullName
                if($seen.ContainsKey($candidate.ToLowerInvariant())) { continue }
                $seen[$candidate.ToLowerInvariant()] = $true
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $candidate
                    if($sig.SignerCertificate -and ([string]$sig.SignerCertificate.Subject).Equals($Publisher, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $result.Add($candidate)
                    }
                } catch {}
            }
        } catch {}

        if($depth -ge $MaxDepth) { continue }
        try {
            foreach($child in Get-ChildItem -LiteralPath $dir -Directory -ErrorAction Stop) {
                $queue.Enqueue([pscustomobject]@{ Path=$child.FullName; Depth=($depth + 1) })
            }
        } catch {}
    }

    if(-not ($result | Where-Object { $_.Equals($resolved, [System.StringComparison]::OrdinalIgnoreCase) })) {
        $result.Insert(0, $resolved)
    }
    return @($result | Select-Object -Unique)
}

function Test-AppGuardProductFamilyCandidate([string]$ProductName, [string]$Publisher) {
    if ([string]::IsNullOrWhiteSpace($ProductName) -or [string]::IsNullOrWhiteSpace($Publisher)) { return $false }
    $name = $ProductName.Trim()
    if ($name.Length -lt 4) { return $false }

    # ProductName-scoped FilePublisher rules are excellent for real application families
    # (for example Google Chrome), but are much too broad for generic runtimes/components.
    $generic = @(
        '.NET','Microsoft .NET','Microsoft® .NET','Microsoft(R) .NET',
        'Windows','Microsoft Windows','Runtime','Application','Setup','Installer',
        'Microsoft Visual C++','Microsoft Visual C++ Runtime'
    )
    foreach($g in $generic) {
        if ($name.Equals($g, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    if ($name -match '(?i)^Microsoft.{0,3}\.NET($|\s)' -or $name -match '(?i)^\.NET($|\s)') { return $false }
    return $true
}

function Get-SupplementalRuleType([string]$XmlPath) {
    if (!(Test-Path -LiteralPath $XmlPath)) { return 'Unknown' }
    [xml]$x = Get-Content -LiteralPath $XmlPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si','urn:schemas-microsoft-com:sipolicy')
    $fileAttrib = $x.SelectSingleNode('//si:FileRules/si:FileAttrib',$ns)
    $publisher = $x.SelectSingleNode('//si:Signers/si:Signer/si:CertPublisher',$ns)
    $allowHash = $x.SelectSingleNode('//si:FileRules/si:Allow[@Hash]',$ns)
    if ($null -ne $fileAttrib -and $null -ne $publisher) { return 'FilePublisher' }
    if ($null -ne $publisher) { return 'Publisher' }
    if ($null -ne $allowHash) { return 'Hash' }
    return 'Generated policy'
}


function Get-DenyRuleType([string]$XmlPath) {
    if (!(Test-Path -LiteralPath $XmlPath)) { return 'Unknown' }
    [xml]$x = Get-Content -LiteralPath $XmlPath -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
    $ns.AddNamespace('si','urn:schemas-microsoft-com:sipolicy')
    $fileAttrib = $x.SelectSingleNode('//si:FileRules/si:FileAttrib',$ns)
    $publisher = $x.SelectSingleNode('//si:Signers/si:Signer/si:CertPublisher',$ns)
    $denyHash = $x.SelectSingleNode('//si:FileRules/si:Deny[@Hash]',$ns)
    if ($null -ne $fileAttrib -and $null -ne $publisher) { return 'FilePublisher Deny' }
    if ($null -ne $publisher) { return 'Publisher Deny' }
    if ($null -ne $denyHash) { return 'Hash Deny' }
    return 'Generated deny policy'
}
