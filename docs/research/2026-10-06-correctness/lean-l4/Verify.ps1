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
. (Join-Path $PSScriptRoot 'AuditSupport.ps1')

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
        'FooLiL2.lean','FooLiL3.lean','FooLiL4.lean','Audit.lean','Verify.ps1','README.md','declarations.json',
        'AuditSupport.ps1','RefreshAudit.ps1','vendor-l2-l3.json','契约与证明边界.md')
    foreach ($folder in @('FooLiL2','FooLiL3','FooLiL4','Checks')) {
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
    $observed = @(Get-LibraryDeclarations)
    $sources = @(Get-LibrarySources)
    $allProofs = $sources + @(Get-ChildItem -LiteralPath 'Checks' -Filter '*.lean') +
        @(Get-Item 'FooLiL2.lean','FooLiL3.lean','FooLiL4.lean','Audit.lean')
    foreach ($file in $allProofs) {
        $source = [System.IO.File]::ReadAllText($file.FullName)
        if ($source -match '\b(sorry|admit|axiom|native_decide|implemented_by|unsafe)\b') {
            throw "Forbidden proof bypass token in $($file.Name)"
        }
    }
    if (($observed | ConvertTo-Json -Depth 4) -ne ($inventory | ConvertTo-Json -Depth 4)) {
        throw 'Declaration inventory changed; review and regenerate the audit.'
    }
    $vendor = Get-Content -Raw -LiteralPath 'vendor-l2-l3.json' | ConvertFrom-Json
    foreach ($entry in $vendor.files) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $entry.path).Hash -ne $entry.sha256) {
            throw "Frozen L2/L3 vendor changed: $($entry.path)"
        }
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
    $build = Invoke-Recorded 'build' 'lake' @('build','FooLiL4','FooLiL4.Controls','FooLiL3','FooLiL3.Controls',
        'FooLiL3.BridgeControls','FooLiL2','FooLiL2.Controls')
    if ($build -match 'warning:|error:') { throw 'Unexpected build diagnostic.' }
    foreach ($file in $sources) {
        $result = Invoke-Recorded ('source-' + $file.Directory.Name + '-' + $file.BaseName) 'lake' @('env','lean',
            ($file.Directory.Name + '/' + $file.Name))
        if ($result -match 'warning:|error:') { throw "Source diagnostic in $($file.Name)" }
    }
    $rootCheck = Invoke-Recorded 'source-root' 'lake' @('env','lean','FooLiL4.lean')
    if ($rootCheck -match 'warning:|error:') { throw 'Root source diagnostic.' }
    foreach ($check in @('FooLiL2.lean','FooLiL3.lean')) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($check)
        $positive = Invoke-Recorded ('positive-' + $name) 'lake' @('env','lean',$check)
        if ($positive -match 'sorryAx|Lean\.ofReduceBool|warning:|error:') { throw "Positive check diagnostic: $check" }
    }
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
    foreach ($check in @('Checks/AbortIgnored.lean','Checks/StrictCutoff.lean','Checks/WrongDimension.lean')) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($check)
        $negative = Invoke-Recorded ('expected-rejection-' + $name) 'lake' @('env','lean',$check) 1
        if ($negative -notmatch 'unsolved goals' -or $negative -notmatch 'False') {
            throw "Negative check failed for an unexpected reason: $check"
        }
    }
    $hashesAfter = @(Get-AuthoredHashes)
    if (($hashesBefore | ConvertTo-Json -Depth 4) -ne ($hashesAfter | ConvertTo-Json -Depth 4)) {
        throw 'An authored file changed during verification; run again on frozen sources.'
    }
    $logs = @(Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' | Sort-Object Name | ForEach-Object {
        [ordered]@{path=$_.Name; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash}
    })
    $report = [ordered]@{
        status='pass_conditional_l4_closed'; verification_status='pass'; conditional_l4_complete=$true
        actual_sampler_contracts_verified=$false; timestamp=(Get-Date -Format o); project_directory=$PSScriptRoot
        lean=$leanVersion; lake=$lakeVersion; powershell=$PSVersionTable.PSVersion.ToString()
        operating_system=[System.Environment]::OSVersion.VersionString
        scope='Conditional L4 from valid master relation, fixed-state C2 dual mass, L2 extension and raw C4 TV; constructed infinite coset ideal law, raw abort-inclusive event, finite uniform tape law'
        exclusions=@('No actual Setup good-event probability certificate','No actual sampler TV contract verification',
            'No actual RNG or seed persistence integration','No security reduction','No parameter selection',
            'No implementation refinement','No full IB-ME correctness proof','No zero-rejection or retry policy change')
        security_claim='none'; declaration_count=$inventory.Count
        theorem_count=@($inventory | Where-Object { $_.kind -eq 'theorem' }).Count
        declaration_counts_by_library=@($inventory | Group-Object { $_.name.Split('.')[0] } | ForEach-Object {
            [ordered]@{library=$_.Name; count=$_.Count; theorems=@($_.Group | Where-Object { $_.kind -eq 'theorem' }).Count}
        })
        vendor_l2_l3=$vendor
        dependencies=$dependencies; commands=@($runs.ToArray()); declaration_axioms=$axioms
        authored_files=$hashesAfter; logs=$logs
    }
    $json = ($report | ConvertTo-Json -Depth 12) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText((Join-Path $LogDirectory 'verification.json'), $json + "`n", $utf8)
    Write-Host "PASS: $($report.theorem_count) theorems, $($inventory.Count) declarations; three false claims rejected; conditional L4 closed."
    Write-Host "Logs: $LogDirectory"
} finally { Pop-Location }
