param(
    [Parameter(Mandatory)]
    [string] $Configuration
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$visualStudio = & $vswhere -latest -products '*' -property installationPath
$toolDirectory = Join-Path $visualStudio 'Common7/IDE/Extensions/Microsoft/CodeCoverage.Console'
$collector = Join-Path $toolDirectory 'Microsoft.CodeCoverage.Console.exe'
$bin = (Resolve-Path "windows/build/$Configuration").Path

foreach ($binary in @('webauthn_test.exe', 'provider_test.exe', 'setup_test.exe', 'quickunlocker.dll')) {
    & $collector instrument (Join-Path $bin $binary)
}

$fixture = (Resolve-Path 'windows/tests/assertions.json').Path
$provider = Join-Path $bin 'quickunlocker.dll'
& $collector collect -o "$bin/verifier.coverage" (Join-Path $bin 'webauthn_test.exe') "$fixture"
& $collector collect -o "$bin/provider.coverage" (Join-Path $bin 'provider_test.exe') "$provider" coverage
& $collector collect -o "$bin/setup.coverage" (Join-Path $bin 'setup_test.exe') "$fixture"
& $collector merge -f cobertura -o coverage-cpp.xml "$bin/verifier.coverage" "$bin/provider.coverage" "$bin/setup.coverage"

[xml] $report = Get-Content coverage-cpp.xml -Raw
$coveredFiles = $report.SelectNodes('//class[lines/line[@hits > 0]]') |
    ForEach-Object { Split-Path $_.filename -Leaf }
foreach ($source in @('webauthn.cpp', 'credprov.cpp', 'enrollment.cpp')) {
    if ($source -notin $coveredFiles) {
        throw "Native coverage has no executed lines for $source."
    }
}
