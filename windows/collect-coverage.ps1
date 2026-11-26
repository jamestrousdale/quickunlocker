$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

# Clang uses the Visual Studio headers, libraries, and Windows SDK.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
& (Join-Path $visualStudio 'Common7/Tools/Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation

$llvm = Join-Path $env:ProgramFiles 'LLVM/bin'
$clang = Join-Path $llvm 'clang-cl.exe'
$profdata = Join-Path $llvm 'llvm-profdata.exe'
$cov = Join-Path $llvm 'llvm-cov.exe'
$build = Join-Path (Resolve-Path 'windows').Path 'build/coverage'

cmake -S windows -B $build -G Ninja "-DCMAKE_CXX_COMPILER=$clang" -DCMAKE_BUILD_TYPE=Release -DQUICKUNLOCKER_COVERAGE=ON
cmake --build $build --parallel --target webauthn_test provider_test setup_test

# Distinguish profiles from different processes and modules.
$profiles = New-Item -ItemType Directory -Path (Join-Path $build "profiles-$([guid]::NewGuid())")
$previousProfile = $env:LLVM_PROFILE_FILE
try {
    $env:LLVM_PROFILE_FILE = Join-Path $profiles.FullName '%m-%p.profraw'
    ctest --test-dir $build --output-on-failure --no-tests=error
} finally {
    $env:LLVM_PROFILE_FILE = $previousProfile
}

$rawFiles = @(Get-ChildItem -LiteralPath $profiles.FullName -Filter '*.profraw' -File | ForEach-Object FullName)
if (-not $rawFiles.Count) { throw 'CTest produced no LLVM coverage profiles.' }
$profile = Join-Path $profiles.FullName 'merged.profdata'
& $profdata merge -sparse -o "$profile" @rawFiles

$sources = @(Get-ChildItem windows/common, windows/credprov, windows/setup -Filter '*.cpp' | ForEach-Object FullName)
$coverageArgs = @(
    'export', '-format=lcov', "-instr-profile=$profile",
    (Join-Path $build 'webauthn_test.exe'),
    '-object', (Join-Path $build 'provider_test.exe'),
    '-object', (Join-Path $build 'quickunlocker.dll'),
    '-object', (Join-Path $build 'setup_test.exe'),
    '-sources'
)
$report = Join-Path $build 'coverage-cpp.lcov'
& $cov @coverageArgs @sources > $report

$coveredFiles = @{}
foreach ($line in Get-Content -LiteralPath $report) {
    if ($line.StartsWith('SF:')) {
        $source = Split-Path $line.Substring(3) -Leaf
    } elseif ($line -match '^DA:\d+,[1-9]\d*(,|$)') {
        $coveredFiles[$source] = $true
    }
}
foreach ($source in @('webauthn.cpp', 'credprov.cpp', 'enrollment.cpp')) {
    if (-not $coveredFiles.ContainsKey($source)) {
        throw "Native coverage has no executed lines for $source."
    }
}
