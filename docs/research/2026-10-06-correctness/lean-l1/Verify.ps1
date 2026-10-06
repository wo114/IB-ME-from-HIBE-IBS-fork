param(
    [string]$LeanHome = '',
    [string]$LogDirectory = ''
)

# Run with PowerShell 7 or Windows PowerShell 5.1. No persistent environment edits.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($LeanHome) {
    . (Join-Path $LeanHome 'Enter-Lean.ps1')
}
if (-not $LogDirectory) {
    $LogDirectory = Join-Path $PSScriptRoot ('verification\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $LogDirectory) {
    throw 'Use a fresh log directory; previous verification records are not overwritten.'
}
New-Item -ItemType Directory -Path $LogDirectory | Out-Null
$LogDirectory = (Resolve-Path -LiteralPath $LogDirectory).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)
$runRecords = New-Object 'System.Collections.Generic.List[object]'

function Invoke-Recorded {
    param([string]$Name, [string]$Command, [string[]]$Arguments, [int]$ExpectedExit = 0)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    # WinPS 5 treats redirected stderr as ErrorRecord. Capture it without masking exit status.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @(& $Command @Arguments 2>&1)
    $code = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    $timer.Stop()
    $body = ($lines | ForEach-Object { $_.ToString() }) -join "`n"
    [System.IO.File]::WriteAllText((Join-Path $LogDirectory ($Name + '.log')), $body + "`n", $utf8)
    $runRecords.Add([ordered]@{
        name = $Name; command = $Command; arguments = $Arguments
        exit_code = $code; expected_exit = $ExpectedExit; seconds = $timer.Elapsed.TotalSeconds
    })
    if ($code -ne $ExpectedExit) { throw "$Name exit $code (expected $ExpectedExit); inspect its log." }
    Write-Host "$Name : expected exit $ExpectedExit confirmed"
    return $body
}

Push-Location $PSScriptRoot
try {
    $sourcePaths = @('FooLiL1.lean', 'FooLiL1/Controls.lean')
    $theorems = @()
    foreach ($path in $sourcePaths) {
        $source = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot $path))
        if ($source -match '\b(sorry|admit|axiom|native_decide|implemented_by|unsafe)\b') {
            throw "Forbidden proof bypass token in $path"
        }
        $prefix = 'FooLiL1.'
        if ($path -like '*/Controls.lean') { $prefix = 'FooLiL1.Controls.' }
        foreach ($match in [regex]::Matches($source, '(?m)^theorem\s+(\w+)')) {
            $theorems += $prefix + $match.Groups[1].Value
        }
    }

    $leanVersion = Invoke-Recorded -Name 'lean-version' -Command 'lean' -Arguments @('--version')
    if ($leanVersion -notmatch 'version 4\.34\.1' -or $leanVersion -notmatch '5045d0056413') {
        throw 'Unexpected Lean version/commit.'
    }
    $lakeVersion = Invoke-Recorded -Name 'lake-version' -Command 'lake' -Arguments @('--version')
    $lock = Get-Content -Raw -LiteralPath 'lake-manifest.json' | ConvertFrom-Json
    $dependencies = @()
    foreach ($package in $lock.packages) {
        $packagePath = Join-Path $PSScriptRoot ('.lake\packages\' + $package.name)
        $head = Invoke-Recorded -Name ('dependency-' + $package.name) -Command 'git' -Arguments @('-C', $packagePath, 'rev-parse', 'HEAD')
        if ($head.Trim() -ne $package.rev) { throw "Dependency mismatch: $($package.name)" }
        $dirty = Invoke-Recorded -Name ('dependency-status-' + $package.name) -Command 'git' -Arguments @('-C', $packagePath, 'status', '--porcelain', '--untracked-files=no')
        if ($dirty.Trim()) { throw "Modified tracked dependency: $($package.name)" }
        $dependencies += [ordered]@{ name = $package.name; revision = $head.Trim() }
    }

    # Check the source afresh, then build importable modules and inspect transitive axioms.
    $sourceCheck = Invoke-Recorded -Name 'source-check' -Command 'lake' -Arguments @('env', 'lean', 'FooLiL1.lean')
    $build = Invoke-Recorded -Name 'build' -Command 'lake' -Arguments @('build', 'FooLiL1', 'FooLiL1.Controls')
    if (($sourceCheck + $build) -match 'warning:|error:') { throw 'Unexpected source/build diagnostic.' }
    $audit = Invoke-Recorded -Name 'axioms-and-statements' -Command 'lake' -Arguments @('env', 'lean', 'Audit.lean')
    $allowed = @('propext', 'Classical.choice', 'Quot.sound')
    $axioms = @()
    foreach ($name in $theorems) {
        $escapedName = [regex]::Escape($name)
        $depMatch = [regex]::Match($audit, "'$escapedName' depends on axioms: \[([^\]]*)\]")
        $noneMatch = [regex]::Match($audit, "'$escapedName' does not depend on any axioms")
        if (-not $depMatch.Success -and -not $noneMatch.Success) { throw "Missing axiom report: $name" }
        $deps = @()
        if ($depMatch.Success) {
            $deps = @($depMatch.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        foreach ($dep in $deps) {
            if ($allowed -notcontains $dep) { throw "Unapproved axiom $dep in $name" }
        }
        $axioms += [ordered]@{ theorem = $name; axioms = $deps }
    }
    if ($theorems.Count -ne 18) { throw 'Review the theorem inventory before accepting changes.' }
    if ($audit -match 'sorryAx|Lean\.ofReduceBool|warning:|error:') { throw 'Axiom/diagnostic audit failed.' }

    $negative = Invoke-Recorded -Name 'expected-rejection-wrong-sign' -Command 'lake' -Arguments @('env', 'lean', 'Checks/WrongSign.lean') -ExpectedExit 1
    if ($negative -notmatch 'decide' -or $negative -notmatch 'false') {
        throw 'Negative test failed for an unexpected reason; inspect its log.'
    }

    $authoredFiles = @('.gitignore', 'lean-toolchain', 'lakefile.lean', 'lake-manifest.json',
        'FooLiL1.lean', 'FooLiL1/Controls.lean', 'Checks/WrongSign.lean', 'Audit.lean', 'Verify.ps1', 'README.md')
    $hashes = @()
    foreach ($path in $authoredFiles) {
        $hashes += [ordered]@{ path = $path; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash }
    }
    $logs = @(Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' | Sort-Object Name | ForEach-Object {
        [ordered]@{ path = $_.Name; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash }
    })
    $report = [ordered]@{
        status = 'pass'; timestamp = (Get-Date -Format o); project_directory = $PSScriptRoot
        lean = $leanVersion; lake = $lakeVersion; powershell = $PSVersionTable.PSVersion.ToString()
        operating_system = [System.Environment]::OSVersion.VersionString
        scope = 'L1 algebraic congruences only; conditional on hB and hz; no probability or security claim'
        security_claim = 'none'; theorem_count = $theorems.Count; dependencies = $dependencies
        commands = @($runRecords.ToArray()); theorem_axioms = $axioms
        authored_files = $hashes; logs = $logs
    }
    [System.IO.File]::WriteAllText((Join-Path $LogDirectory 'verification.json'), ($report | ConvertTo-Json -Depth 10) + "`n", $utf8)
    Write-Host "PASS: 18 theorems audited; wrong-sign assertion rejected. Logs: $LogDirectory"
} finally {
    Pop-Location
}
