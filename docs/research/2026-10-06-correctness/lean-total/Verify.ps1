param([string]$LogDirectory = (Join-Path $PSScriptRoot ('verification/run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))))
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
Push-Location $PSScriptRoot
$runs = [System.Collections.Generic.List[object]]::new()
function Invoke-Recorded($Name, $Exe, $Arguments, $Expected = 0) {
    $text = (& $Exe @Arguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
    [IO.File]::WriteAllText((Join-Path $LogDirectory ($Name+'.log')), $text, $utf8)
    $runs.Add([ordered]@{name=$Name; executable=$Exe; arguments=$Arguments; exit_code=$code; expected=$Expected})
    if ($code -ne $Expected) { throw "$Name exit $code (expected $Expected): $text" }
    return $text
}
function Get-AuthoredHashes {
    $files = @(Get-ChildItem -File -Filter '*.lean')
    foreach ($dir in @('FooLiL2','FooLiL3','FooLiL4','FooLiTotal','Checks')) {
        $files += @(Get-ChildItem -LiteralPath $dir -File -Filter '*.lean')
    }
    $files += @(Get-Item -LiteralPath 'lake-manifest.json','lean-toolchain','Verify.ps1')
    foreach ($f in ($files | Sort-Object FullName)) {
        [ordered]@{path=[IO.Path]::GetRelativePath($PSScriptRoot,$f.FullName).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $f.FullName).Hash}
    }
}
try {
    $sources = @(Get-Item FooLiL1.lean)
    foreach ($library in @('FooLiL2','FooLiL3','FooLiL4','FooLiTotal')) {
        $sources += @(Get-ChildItem -LiteralPath $library -Filter '*.lean' -File | Sort-Object Name)
    }
    $inventory = @()
    foreach ($file in $sources) {
        $source = [IO.File]::ReadAllText($file.FullName)
        if ($source -match '(?m)^\s*(axiom|opaque)\s' -or $source -match '\b(sorry|admit|native_decide)\b') {
            throw "Forbidden proof construct in $($file.FullName)"
        }
        $ns = [regex]::Matches($source, '(?m)^namespace\s+([\w.]+)\s*$')
        if ($ns.Count -ne 1) { throw "Review namespace inventory: $($file.FullName)" }
        foreach ($m in [regex]::Matches($source, '(?m)^(?:@\[[^\]]+\]\s*)?(?:noncomputable\s+)?(theorem|def|lemma|instance|abbrev)\s+([\w\x27]+)')) {
            $inventory += [ordered]@{name=$ns[0].Groups[1].Value+'.'+$m.Groups[2].Value;kind=$m.Groups[1].Value;file=[IO.Path]::GetRelativePath($PSScriptRoot,$file.FullName).Replace('\','/')}
        }
    }
    $imports = @('import FooLiTotal','import FooLiTotal.Controls','import FooLiL1','import FooLiL2.Controls',
        'import FooLiL3.Controls','import FooLiL3.BridgeControls','import FooLiL4.Controls')
    $lines = $imports + @($inventory | ForEach-Object { '#print axioms '+$_.name })
    foreach ($name in @('FooLiTotal.i1_from_external_mp12_geometry','FooLiTotal.i2_from_raw_hybrids',
        'FooLiTotal.iid_integerGaussian_quality_tail','FooLiTotal.i4_from_gaussian_projection',
        'FooLiTotal.bind_event_bound','FooLiTotal.t1_from_uniform_stage_contracts',
        'FooLiTotal.l1_accepts_with_norm','FooLiTotal.measure_model_transfer')) { $lines += '#check @'+$name }
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Audit.lean'), ($lines -join "`n")+"`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'declarations.json'), ($inventory | ConvertTo-Json -Depth 5)+"`n", $utf8)
    $before = @(Get-AuthoredHashes)
    $lean = Invoke-Recorded 'lean-version' 'lean' @('--version')
    if ($lean -notmatch '4\.34\.1') { throw 'Unexpected Lean version' }
    $manifest = Get-Content -LiteralPath 'lake-manifest.json' -Raw | ConvertFrom-Json
    $dependencies = @()
    foreach ($package in $manifest.packages) {
        $path = Join-Path '.lake/packages' $package.name
        $head = Invoke-Recorded ('revision-'+$package.name) 'git' @('-C',$path,'rev-parse','HEAD')
        if ($head.Trim() -ne $package.rev) { throw "Dependency revision mismatch $($package.name)" }
        $status = Invoke-Recorded ('status-'+$package.name) 'git' @('-C',$path,'status','--porcelain','--untracked-files=no')
        if ($status.Trim()) { throw "Modified tracked dependency $($package.name)" }
        $dependencies += [ordered]@{name=$package.name; revision=$head.Trim()}
    }
    $build = Invoke-Recorded 'build' 'lake' @('build','FooLiTotal','FooLiTotal.Controls',
        'FooLiL2.Controls','FooLiL3.Controls','FooLiL3.BridgeControls','FooLiL4.Controls')
    if ($build -match 'warning:|error:') { throw "Build diagnostics: $build" }
    foreach ($file in (Get-ChildItem FooLiTotal -Filter '*.lean' -File | Sort-Object Name)) {
        $check = Invoke-Recorded ('source-'+$file.BaseName) 'lake' @('env','lean',('FooLiTotal/'+$file.Name))
        if ($check -match 'warning:|error:') { throw "Source diagnostic: $check" }
    }
    $audit = Invoke-Recorded 'axioms-and-statements' 'lake' @('env','lean','Audit.lean')
    $allowed = @('propext','Classical.choice','Quot.sound')
    $axioms = @()
    foreach ($item in $inventory) {
        $name = [regex]::Escape($item.name)
        $m = [regex]::Match($audit, "'$name' depends on axioms: \[([^\]]*)\]")
        $none = [regex]::Match($audit, "'$name' does not depend on any axioms")
        if (-not $m.Success -and -not $none.Success) { throw "Missing axiom report: $($item.name)" }
        $deps = @()
        if ($m.Success) { $deps = @($m.Groups[1].Value -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_}) }
        foreach ($dep in $deps) { if ($dep -notin $allowed) { throw "Unexpected axiom $dep" } }
        $axioms += [ordered]@{name=$item.name; kind=$item.kind; axioms=$deps}
    }
    if ($audit -match 'sorryAx|Lean\.ofReduceBool|warning:|error:') { throw 'Axiom audit diagnostics' }
    $tailCheck = Invoke-Recorded 'master-tail-boundaries' 'lake' @('env','lean','Checks/MasterTailAxioms.lean')
    if ($tailCheck -match 'sorryAx|warning:|error:') { throw 'Master tail check diagnostics' }
    foreach ($name in @('DroppedModelGap','ErasedSetupAbort','WrongBasisConstant')) {
        $negative = Invoke-Recorded ('negative-'+$name) 'lake' @('env','lean',('Checks/'+$name+'.lean')) 1
        if ($negative -notmatch 'unsolved goals' -or $negative -notmatch 'False') { throw "Wrong rejection reason $name" }
    }
    $after = @(Get-AuthoredHashes)
    if (($before | ConvertTo-Json -Depth 5) -ne ($after | ConvertTo-Json -Depth 5)) { throw 'Authored sources changed during verification' }
    $report = [ordered]@{
        verification_status='pass'; deliverable_status='partial_formal_closure'; timestamp=(Get-Date -Format o)
        full_initialization_formalization_complete=$false; end_to_end_runtime_theorem_complete=$false
        ideal_radial_I3_complete=$true; conditional_stage_composition_checked=$true
        SHAKE_instantiation_gap_proved_small=$false; actual_sampler_TV_refinement_verified=$false
        security_claim='none'; parameters='symbolic; no competition parameter selection'
        open_obligations=@('MP12 gadget basis and lifted GS bound; GS-to-actual-dual-mass theorem',
            'Actual scalar finite sampler hybrid/coupling refinement for I2 C3 C4',
            'Coordinate/geometric I3 branch (min of two bounds) not formalized',
            'RO table/Python state machine and hash-to-Zq refinement into the PMF experiment',
            'Concrete SHAKE and OS source assumptions; no proved small instantiation gaps')
        lean=$lean.Trim(); dependencies=$dependencies; commands=@($runs.ToArray())
        declarations=$inventory; axiom_audit=$axioms; authored_files=$after
        logs=@(Get-ChildItem $LogDirectory -File -Filter '*.log' | Sort-Object Name | ForEach-Object {
            [ordered]@{path=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
        })
    }
    [IO.File]::WriteAllText((Join-Path $LogDirectory 'verification.json'), ($report | ConvertTo-Json -Depth 12)+"`n", $utf8)
    Write-Host "PASS kernel checks; PARTIAL full closure. $($inventory.Count) declarations; 3 expected false-claim rejections."
    Write-Host "Report: $LogDirectory"
} finally { Pop-Location }
