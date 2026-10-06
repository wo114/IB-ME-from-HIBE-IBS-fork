param([string]$LeanHome = '', [string]$LogDirectory = '')

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($LeanHome) { . (Join-Path $LeanHome 'Enter-Lean.ps1') }
if (-not $LogDirectory) {
    $LogDirectory = Join-Path $PSScriptRoot ('verification\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $LogDirectory) { throw 'Use a fresh log directory.' }
New-Item -ItemType Directory -Path $LogDirectory | Out-Null
$LogDirectory = (Resolve-Path -LiteralPath $LogDirectory).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)
$runs = New-Object 'System.Collections.Generic.List[object]'

function Invoke-Recorded {
    param([string]$Name, [string]$Command, [string[]]$Arguments, [int]$ExpectedExit = 0)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @(& $Command @Arguments 2>&1)
    $code = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    $timer.Stop()
    $body = ($lines | ForEach-Object { $_.ToString() }) -join "`n"
    [System.IO.File]::WriteAllText((Join-Path $LogDirectory ($Name + '.log')), $body + "`n", $utf8)
    $runs.Add([ordered]@{name=$Name; command=$Command; arguments=$Arguments;
        exit_code=$code; expected_exit=$ExpectedExit; seconds=$timer.Elapsed.TotalSeconds})
    if ($code -ne $ExpectedExit) { throw "$Name exit $code; expected $ExpectedExit." }
    Write-Host "$Name : expected exit $ExpectedExit confirmed"
    return $body
}

function Get-AuthoredHashes {
    $paths = @('.gitignore','lean-toolchain','lakefile.lean','lake-manifest.json',
        'FooLiL3.lean','Audit.lean','Verify.ps1','README.md','declarations.json')
    foreach ($folder in @('FooLiL3','Checks','reviews')) {
        $paths += @(Get-ChildItem -LiteralPath $folder -File | ForEach-Object { $folder + '/' + $_.Name })
    }
    foreach ($path in ($paths | Sort-Object)) {
        [ordered]@{path=$path; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash}
    }
}

Push-Location $PSScriptRoot
try {
    $hashesBefore = @(Get-AuthoredHashes)
    $inventory = @(Get-Content -Raw -LiteralPath 'declarations.json' | ConvertFrom-Json)
    $observed = @()
    $sources = @(Get-ChildItem -LiteralPath 'FooLiL3' -Filter '*.lean' | Sort-Object Name)
    foreach ($file in $sources) {
        $source = [System.IO.File]::ReadAllText($file.FullName)
        if ($source -match '\b(sorry|admit|axiom|native_decide|implemented_by|unsafe)\b') {
            throw "Forbidden proof bypass token in $($file.Name)"
        }
        $prefix = 'FooLiL3.'
        if ($file.Name -eq 'Controls.lean') { $prefix += 'Controls.' }
        foreach ($match in [regex]::Matches($source,
            '(?m)^(?:@\[[^\]]+\]\s*)?(?:noncomputable\s+)?(theorem|def)\s+(\w+)')) {
            $observed += $prefix + $match.Groups[2].Value
        }
    }
    if (($observed -join "`n") -ne (($inventory | ForEach-Object { $_.name }) -join "`n")) {
        throw 'Declaration inventory changed; review and regenerate the audit.'
    }
    $leanVersion = Invoke-Recorded 'lean-version' 'lean' @('--version')
    if ($leanVersion -notmatch 'version 4\.34\.1' -or $leanVersion -notmatch '5045d0056413') {
        throw 'Unexpected Lean version/commit.'
    }
    $lakeVersion = Invoke-Recorded 'lake-version' 'lake' @('--version')
    $lock = Get-Content -Raw -LiteralPath 'lake-manifest.json' | ConvertFrom-Json
    $dependencies = @()
    foreach ($package in $lock.packages) {
        $packagePath = Join-Path $PSScriptRoot ('.lake\packages\' + $package.name)
        $head = Invoke-Recorded ('dependency-' + $package.name) 'git' @('-C',$packagePath,'rev-parse','HEAD')
        if ($head.Trim() -ne $package.rev) { throw "Dependency mismatch: $($package.name)" }
        $dirty = Invoke-Recorded ('dependency-status-' + $package.name) 'git' @('-C',$packagePath,'status','--porcelain','--untracked-files=no')
        if ($dirty.Trim()) { throw "Modified tracked dependency: $($package.name)" }
        $dependencies += [ordered]@{name=$package.name; revision=$head.Trim()}
    }
    $build = Invoke-Recorded 'build' 'lake' @('build','FooLiL3','FooLiL3.Controls')
    if ($build -match 'warning:|error:') { throw 'Unexpected build diagnostic.' }
    foreach ($file in $sources) {
        $result = Invoke-Recorded ('source-' + $file.BaseName) 'lake' @('env','lean',('FooLiL3/' + $file.Name))
        if ($result -match 'warning:|error:') { throw "Source diagnostic in $($file.Name)" }
    }
    $rootCheck = Invoke-Recorded 'source-root' 'lake' @('env','lean','FooLiL3.lean')
    if ($rootCheck -match 'warning:|error:') { throw 'Root source diagnostic.' }
    $audit = Invoke-Recorded 'axioms-and-statements' 'lake' @('env','lean','Audit.lean')
    $allowed = @('propext','Classical.choice','Quot.sound')
    $axioms = @()
    foreach ($declaration in $inventory) {
        $name = $declaration.name
        $escapedName = [regex]::Escape($name)
        $depMatch = [regex]::Match($audit, "'$escapedName' depends on axioms: \[([^\]]*)\]")
        $noneMatch = [regex]::Match($audit, "'$escapedName' does not depend on any axioms")
        if (-not $depMatch.Success -and -not $noneMatch.Success) { throw "Missing audit: $name" }
        $deps = @()
        if ($depMatch.Success) {
            $deps = @($depMatch.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        foreach ($dep in $deps) { if ($allowed -notcontains $dep) { throw "Unapproved dependency: $dep in $name" } }
        $axioms += [ordered]@{declaration=$name; kind=$declaration.kind; axioms=$deps}
    }
    if ($audit -match 'sorryAx|Lean\.ofReduceBool|warning:|error:') { throw 'Axiom audit failed.' }
    $negative = Invoke-Recorded 'expected-rejection-missing-column-factor' 'lake' @('env','lean','Checks/MissingColumnFactor.lean') 1
    if ($negative -notmatch 'unsolved goals' -or $negative -notmatch 'False') {
        throw 'The negative test failed for an unexpected reason.'
    }
    $hashesAfter = @(Get-AuthoredHashes)
    if (($hashesBefore | ConvertTo-Json -Depth 4) -ne ($hashesAfter | ConvertTo-Json -Depth 4)) {
        throw 'An authored file changed during verification; run again on frozen sources.'
    }
    $logs = @(Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' | Sort-Object Name | ForEach-Object {
        [ordered]@{path=$_.Name; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash}
    })
    $report = [ordered]@{
        status='pass_scoped_wip_overall'; verification_status='pass'; full_l3_complete=$false; timestamp=(Get-Date -Format o); project_directory=$PSScriptRoot
        lean=$leanVersion; lake=$lakeVersion; powershell=$PSVersionTable.PSVersion.ToString()
        operating_system=[System.Environment]::OSVersion.VersionString
        scope='L3 WIP: conditional coset-Gaussian tail, matrix norms, raw-event TV assembly'
        exclusions=@('C2 to CosetMassComparison not proved','C3 product law to marginal/support contracts not instantiated','No sampler contract verification','No full L3 or L4 proof','No security reduction','No parameter selection','No implementation refinement')
        security_claim='none'; declaration_count=$inventory.Count
        theorem_count=@($inventory | Where-Object { $_.kind -eq 'theorem' }).Count
        dependencies=$dependencies; commands=@($runs.ToArray()); declaration_axioms=$axioms
        authored_files=$hashesAfter; logs=$logs
    }
    $json = ($report | ConvertTo-Json -Depth 12) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText((Join-Path $LogDirectory 'verification.json'), $json + "`n", $utf8)
    Write-Host "PASS: $($report.theorem_count) theorems, $($inventory.Count) declarations; false bound rejected; full L3 remains WIP."
    Write-Host "Logs: $LogDirectory"
} finally { Pop-Location }
