param(
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$FinalRun,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
# This script audits the copied package against frozen source and test evidence,
# creates a derived delivery manifest, then makes exact output-directory copies.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$base = Join-Path $Repository 'docs/research/2026-10-06-correctness'
$package = Join-Path $base 'lean-total'
$runDir = Join-Path (Join-Path $package 'verification') $FinalRun
$audit = Get-Content -LiteralPath (Join-Path $runDir 'verification.json') -Raw | ConvertFrom-Json
if ($audit.verification_status -ne 'pass' -or $audit.deliverable_status -ne 'partial_formal_closure') { throw 'Wrong formal evidence status' }
foreach ($item in $audit.authored_files) {
    if ((Get-FileHash -LiteralPath (Join-Path $package $item.path)).Hash -ne $item.sha256) { throw "Formal source mismatch $($item.path)" }
}
foreach ($item in $audit.logs) {
    if ((Get-FileHash -LiteralPath (Join-Path $runDir $item.path)).Hash -ne $item.sha256) { throw "Formal log mismatch $($item.path)" }
}
$vendorPaths = @('FooLiL1.lean','FooLiL2.lean','FooLiL3.lean','FooLiL4.lean')
foreach ($lib in @('FooLiL2','FooLiL3','FooLiL4')) {
    $vendorPaths += @(Get-ChildItem -LiteralPath (Join-Path $package $lib) -File -Filter '*.lean' |
        ForEach-Object { $lib+'/'+$_.Name })
}
$vendor = @()
foreach ($path in $vendorPaths) {
    $sourceBase = if ($path -eq 'FooLiL1.lean') { Join-Path $base 'lean-l1' } else { Join-Path $base 'lean-l4' }
    $source = (Get-FileHash -LiteralPath (Join-Path $sourceBase $path)).Hash
    $copy = (Get-FileHash -LiteralPath (Join-Path $package $path)).Hash
    if ($source -ne $copy) { throw "Frozen vendor differs: $path" }
    $vendor += [ordered]@{path=$path;sha256=$copy}
}
$tests = Get-Content -LiteralPath (Join-Path $base 'shake-model/verification.json') -Raw | ConvertFrom-Json
foreach ($item in $tests.source_files) {
    if ((Get-FileHash -LiteralPath (Join-Path $Repository $item.path)).Hash -ne $item.sha256) { throw "Runtime test source differs: $($item.path)" }
}
if ((Get-FileHash -LiteralPath (Join-Path $base 'shake-model/pytest.log')).Hash -ne $tests.log_sha256) { throw 'Test log differs' }
$paths = @()
foreach ($dir in @('lean-total','shake-model')) {
    $paths += @(Get-ChildItem -LiteralPath (Join-Path $base $dir) -File -Recurse |
        Where-Object { $_.Name -ne 'delivery.json' } |
        ForEach-Object { [IO.Path]::GetRelativePath($Repository,$_.FullName).Replace('\','/') })
}
$paths += @('docs/research/2026-10-06-correctness/README.md',
    'experiments/research/foo_li_oracle_model.py','tests/test_foo_li_oracle_model.py')
$inventory = @($paths | Sort-Object -Unique | ForEach-Object {
    [ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $Repository $_)).Hash}
})
$delivery = [ordered]@{
    timestamp=(Get-Date -Format o); final_verification_run=$FinalRun; status='partial_formal_closure'
    unchanged_frozen_vendor=$vendor; verified_source_and_log_hashes=$true
    declarations=$audit.declarations.Count; theorems=@($audit.declarations | Where-Object kind -eq theorem).Count
    new_declarations=@($audit.declarations | Where-Object name -like 'FooLiTotal.*').Count
    new_theorems=@($audit.declarations | Where-Object { $_.name -like 'FooLiTotal.*' -and $_.kind -eq 'theorem' }).Count
    formal_commands=$audit.commands.Count; expected_negative_controls=3; runtime_tests=$tests.tests_passed
    files=$inventory; inventory_excludes_self=$true; security_claim='none'
}
$manifestPath = Join-Path $package 'delivery.json'
[IO.File]::WriteAllText($manifestPath, ($delivery | ConvertTo-Json -Depth 9)+"`n", $utf8)
foreach ($item in $inventory) {
    $path = $item.path
    $docPrefix = 'docs/research/2026-10-06-correctness/'
    $relative = if ($path.StartsWith($docPrefix)) { $path.Substring($docPrefix.Length) } else { 'shake-model/source/'+$path }
    $dest = Join-Path $OutputRoot $relative
    New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $Repository $path) -Destination $dest
    if ((Get-FileHash -LiteralPath $dest).Hash -ne $item.sha256) { throw "Output mirror differs: $path" }
}
$manifestCopy = Join-Path $OutputRoot 'lean-total/delivery.json'
Copy-Item -LiteralPath $manifestPath -Destination $manifestCopy
if ((Get-FileHash $manifestPath).Hash -ne (Get-FileHash $manifestCopy).Hash) { throw 'Manifest copy differs' }
Write-Host "PASS: $($vendor.Count) frozen vendor files identical; $($inventory.Count) delivered files plus manifest mirrored exactly."
Write-Host "Formal declarations: $($delivery.declarations), new theorems: $($delivery.new_theorems); runtime tests: $($delivery.runtime_tests)."
