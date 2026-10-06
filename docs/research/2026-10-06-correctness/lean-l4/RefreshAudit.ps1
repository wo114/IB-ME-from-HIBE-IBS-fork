# Mechanical generation only. Review the declaration diff before verification.
param([string]$VendorSource = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AuditSupport.ps1')
$utf8 = New-Object System.Text.UTF8Encoding($false)
Push-Location $PSScriptRoot
try {
    $inventory = @(Get-LibraryDeclarations)
    $json = ($inventory | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot 'declarations.json'), $json + "`n", $utf8)
    $lines = @('import FooLiL4', 'import FooLiL4.Controls',
        'import FooLiL3', 'import FooLiL3.Controls', 'import FooLiL3.BridgeControls',
        'import FooLiL2', 'import FooLiL2.Controls', '')
    $lines += @($inventory | ForEach-Object { '#print axioms ' + $_.name })
    $lines += @('', '#check @FooLiL4.l4_from_master_relation',
        '#check @FooLiL4.l4_from_c2_c4', '#check @FooLiL4.l4_for_uniform_tape_program',
        '#check @FooLiL4.rawTapeMeasure_event', '#check @FooLiL4.idealSignature_failure_le',
        '#check @FooLiL3.l3_from_c2_c3',
        '#check @FooLiL3.l3_from_smoothing_and_product_ideal',
        '#check @FooLiL3.cosetMassComparison_of_smoothing',
        '#check @FooLiL3.normalized_coset_mass_deviation',
        '#check @FooLiL3.coset_poisson', '#check @FooLiL3.idealDelegationMeasure_rectangle')
    [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot 'Audit.lean'), ($lines -join "`n") + "`n", $utf8)
    if ($VendorSource) {
        $vendorPaths = @('FooLiL2.lean','FooLiL3.lean')
        foreach ($library in @('FooLiL2','FooLiL3')) {
            $vendorPaths += @(Get-ChildItem -LiteralPath $library -Filter '*.lean' -File |
                Sort-Object Name | ForEach-Object { $library + '/' + $_.Name })
        }
        $vendor = @()
        foreach ($path in $vendorPaths) {
            $original = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $VendorSource $path)).Hash
            $copy = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
            if ($original -ne $copy) { throw "Vendor differs from frozen L2/L3: $path" }
            $vendor += [ordered]@{path=$path; sha256=$original}
        }
        $manifest = [ordered]@{
            source_commit='4e63f2dd85deefb89366fbbedb89c373367861d4'
            source_directory='../lean-l3'; files=$vendor
            purpose='Byte-identical L2/L3 sources, compiled and transitively audited again in L4'
        }
        $vendorJson = ($manifest | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot 'vendor-l2-l3.json'), $vendorJson + "`n", $utf8)
    }
    Write-Host "Generated audit for $($inventory.Count) public declarations."
} finally { Pop-Location }
