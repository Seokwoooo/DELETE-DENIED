[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$HookPath,
    [Parameter(Position = 1)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Iterations = 100,
    [Parameter(Position = 2)]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$Warmup = 10
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $HookPath -PathType Leaf)) {
    throw "hook does not exist: $HookPath"
}

$hook = (Resolve-Path -LiteralPath $HookPath).Path
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = Split-Path -Parent $scriptDir
$cargoToml = Join-Path $repoDir 'crates/delete-denied-hook/Cargo.toml'
$versionLine = Select-String -Path $cargoToml -Pattern '^version = "([^"]+)"' | Select-Object -First 1
$hookVersion = if ($versionLine) { $versionLine.Matches[0].Groups[1].Value } else { 'unknown' }
$commit = 'unknown'
try {
    $gitDir = Join-Path $repoDir '.git'
    $head = (Get-Content -LiteralPath (Join-Path $gitDir 'HEAD') -Raw).Trim()
    if ($head -match '^ref: (.+)$') {
        $refPath = Join-Path $gitDir $Matches[1]
        if (Test-Path -LiteralPath $refPath) { $head = (Get-Content -LiteralPath $refPath -Raw).Trim() }
    }
    if ($head.Length -ge 7) { $commit = $head.Substring(0, 7) }
} catch { $commit = 'unknown' }

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("delete-denied-bench-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $fixtureRootPath = Join-Path $fixtureRoot 'root'
    $fixtureHome = Join-Path $fixtureRootPath 'Users/alice'
    $project = Join-Path $fixtureHome 'Documents/project'
    $cwd = Join-Path $project 'src'
    New-Item -ItemType Directory -Force -Path $cwd, (Join-Path $fixtureHome 'Desktop'), (Join-Path $fixtureHome 'Downloads'), (Join-Path $project 'build') | Out-Null
    $policyPath = Join-Path $fixtureRoot 'policy.json'
    $policy = [ordered]@{
        schema_version = 1
        variables = [ordered]@{ HOME = $fixtureHome; USERPROFILE = $fixtureHome }
        protected_paths = @(
            [ordered]@{ kind = 'filesystem-root'; logical = $fixtureRootPath; canonical = $fixtureRootPath; case_sensitive = $true }
            [ordered]@{ kind = 'users-parent'; logical = (Join-Path $fixtureRootPath 'Users'); canonical = (Join-Path $fixtureRootPath 'Users'); case_sensitive = $true }
            [ordered]@{ kind = 'home'; logical = '${HOME}'; canonical = $fixtureHome; case_sensitive = $false }
            [ordered]@{ kind = 'documents'; logical = '${HOME}/Documents'; canonical = (Join-Path $fixtureHome 'Documents'); case_sensitive = $false }
            [ordered]@{ kind = 'desktop'; logical = '${HOME}/Desktop'; canonical = (Join-Path $fixtureHome 'Desktop'); case_sensitive = $false }
            [ordered]@{ kind = 'downloads'; logical = '${HOME}/Downloads'; canonical = (Join-Path $fixtureHome 'Downloads'); case_sensitive = $false }
        )
    }
    $policy | ConvertTo-Json -Compress -Depth 8 | Set-Content -LiteralPath $policyPath -NoNewline

    function New-HookInput([string]$Command) {
        return ([ordered]@{
            hook_event_name = 'PreToolUse'
            tool_name = 'Bash'
            cwd = $cwd
            permission_mode = 'danger-full-access'
            tool_input = [ordered]@{ command = $Command }
        } | ConvertTo-Json -Compress -Depth 8)
    }

    $safeInput = New-HookInput 'git status'
    $allowInput = New-HookInput ("rm -rf " + (Join-Path $project 'build'))
    $denyInput = New-HookInput ("rm -rf " + $fixtureHome)

    function Invoke-Hook([string]$InputJson, [ValidateSet('allow', 'deny')][string]$Expected) {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $hook
        $quotedPolicy = $policyPath.Replace('"', '\\"')
        $startInfo.Arguments = "--policy `"$quotedPolicy`""
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        $clock = [Diagnostics.Stopwatch]::StartNew()
        [void]$process.Start()
        $process.StandardInput.Write($InputJson)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $clock.Stop()
        if ($process.ExitCode -ne 0 -or $stderr.Length -ne 0) {
            throw "hook failed during benchmark (exit $($process.ExitCode), stderr length $($stderr.Length))"
        }
        if ($Expected -eq 'allow' -and $stdout.Length -ne 0) {
            throw "allow hook output was not empty"
        }
        if ($Expected -eq 'deny' -and ($stdout.Length -gt 4096 -or $stdout -notmatch '^\{"hookSpecificOutput":.*\"permissionDecision\":\"deny\"')) {
            throw "deny hook output was not bounded structured JSON"
        }
        $elapsedNs = [long](($clock.ElapsedTicks * 1000000000.0) / [Diagnostics.Stopwatch]::Frequency)
        $rss = try { [long]$process.PeakWorkingSet64 } catch { $null }
        $process.Dispose()
        return [pscustomobject]@{ ElapsedNs = $elapsedNs; PeakRss = $rss; Stdout = $stdout }
    }

    foreach ($case in @(@{ Input = $safeInput; Expected = 'allow' }, @{ Input = $allowInput; Expected = 'allow' }, @{ Input = $denyInput; Expected = 'deny' })) {
        for ($i = 0; $i -lt $Warmup; $i++) { [void](Invoke-Hook $case.Input $case.Expected) }
    }
    $safeSamples = [System.Collections.Generic.List[long]]::new()
    $allowSamples = [System.Collections.Generic.List[long]]::new()
    $denySamples = [System.Collections.Generic.List[long]]::new()
    $peakRss = $null
    for ($i = 0; $i -lt $Iterations; $i++) {
        $safe = Invoke-Hook $safeInput 'allow'
        $allow = Invoke-Hook $allowInput 'allow'
        $deny = Invoke-Hook $denyInput 'deny'
        $safeSamples.Add($safe.ElapsedNs)
        $allowSamples.Add($allow.ElapsedNs)
        $denySamples.Add($deny.ElapsedNs)
        foreach ($sample in @($safe, $allow, $deny)) {
            if ($null -ne $sample.PeakRss -and ($null -eq $peakRss -or $sample.PeakRss -gt $peakRss)) { $peakRss = $sample.PeakRss }
        }
    }

    function Get-Stats([System.Collections.Generic.List[long]]$Samples) {
        $sorted = @($Samples | Sort-Object)
        $p50Index = [math]::Max(0, [math]::Ceiling($sorted.Count * 0.50) - 1)
        $p95Index = [math]::Max(0, [math]::Ceiling($sorted.Count * 0.95) - 1)
        return [ordered]@{ p50_ns = $sorted[$p50Index]; p95_ns = $sorted[$p95Index]; max_ns = $sorted[$sorted.Count - 1] }
    }

    $result = [ordered]@{
        os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        hook_version = $hookVersion
        commit = $commit
        build_profile = 'release'
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        iterations = $Iterations
        warmup = $Warmup
        binary_size_bytes = (Get-Item -LiteralPath $hook).Length
        safe = Get-Stats $safeSamples
        suspicious_allow = Get-Stats $allowSamples
        suspicious_deny = Get-Stats $denySamples
        peak_rss_bytes = $peakRss
        method = 'one short-lived process per sample; Stopwatch wall-clock duration'
        limitations = @('Peak RSS is best effort from Process.PeakWorkingSet64 and may be unavailable on some Windows runners.', 'Process startup and stdin parsing are included; filesystem fixtures are temporary and local.')
    }
    $result | ConvertTo-Json -Compress -Depth 8
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}
