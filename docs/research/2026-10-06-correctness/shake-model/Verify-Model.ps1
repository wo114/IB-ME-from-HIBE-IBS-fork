param([string]$Repository = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$paths = @('experiments/research/foo_li_oracle_model.py','tests/test_foo_li_oracle_model.py',
    'experiments/research/foo_li_runtime_reference.py','experiments/research/foo_li_initialization.py',
    'experiments/research/online_mp12_reference.py','experiments/research/online_gaussian_reference.py',
    'experiments/research/gaussian_reference.py','experiments/research/mp12_sampled_reference.py',
    'tests/test_foo_li_runtime_reference.py','tests/test_online_sampling_reference.py','tests/test_encoding.py',
    'src/ibme/core/hashing.py','src/ibme/core/randomness.py','src/ibme/core/encoding.py')
function Hash-Sources {
    foreach ($path in $paths) {
        [ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath (Join-Path $Repository $path)).Hash}
    }
}
$before = @(Hash-Sources)
$resolved = (Resolve-Path -LiteralPath $Repository).Path
if ($resolved -notmatch '^([A-Za-z]):\\') { throw 'Expected local Windows repository path' }
$wslRoot = '/mnt/'+$Matches[1].ToLower()+'/'+$resolved.Substring(3).Replace('\','/')
$command = 'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_foo_li_oracle_model.py tests/test_foo_li_runtime_reference.py tests/test_online_sampling_reference.py tests/test_encoding.py'
$result = (& wsl.exe -d Ubuntu-24.04 --cd $wslRoot bash -lc $command 2>&1 | Out-String)
$code = $LASTEXITCODE
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'pytest.log'), $result, $utf8)
if ($code -ne 0 -or $result -notmatch '195 passed' -or $result -match '\d+ skipped|\d+ failed') {
    throw "Unexpected regression outcome (exit $code): $result"
}
$after = @(Hash-Sources)
if (($before | ConvertTo-Json) -ne ($after | ConvertTo-Json)) { throw 'Sources changed during test run' }
$report = [ordered]@{
    timestamp=(Get-Date -Format o); verification_status='pass'; tests_passed=195
    tests_new=6; command=$command; environment='WSL Ubuntu-24.04; prescribed ~/miniconda3/envs/sage'
    exit_code=$code; source_files=$after; log_sha256=(Get-FileHash (Join-Path $PSScriptRoot 'pytest.log')).Hash
    scope='Model table semantics and injected lifecycle; existing runtime, samplers and encoding regressions'
    randomness_proved=$false; SHAKE_instantiation_proved=$false; security_claim='none'
    test_parameters='Existing ResearchConfig small_config; q=3,n=m_bar=1; deterministic test sources'
    note='The model harness is ideal only under ideal source reads. Deterministic fixtures test behavior, not randomness.'
}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'verification.json'), ($report | ConvertTo-Json -Depth 6)+"`n", $utf8)
Write-Host 'PASS 195 tests. No claim of SHAKE/randomness equivalence.'
