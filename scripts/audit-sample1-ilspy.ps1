[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LosslessAssembly,

    [Parameter(Mandatory)]
    [string] $OptimizedAssembly,

    [Parameter(Mandatory)]
    [string] $ReferenceDirectory,

    [string] $IlSpyCmd = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($IlSpyCmd)) {
    $command = Get-Command ilspycmd.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $IlSpyCmd = $command.Source
    }
    else {
        $IlSpyCmd = Join-Path $env:USERPROFILE '.dotnet\tools\ilspycmd.exe'
    }
}
foreach ($path in @($LosslessAssembly, $OptimizedAssembly, $ReferenceDirectory, $IlSpyCmd)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required ILSpy audit path does not exist: $path"
    }
}

$workRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ("AgileDevirtualizer-ilspy-{0}" -f [Guid]::NewGuid().ToString('N'))
$losslessDirectory = Join-Path $workRoot 'lossless'
$optimizedDirectory = Join-Path $workRoot 'optimized'

function Invoke-Decompile([string] $Assembly, [string] $OutputDirectory) {
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    & $IlSpyCmd --disable-updatecheck --no-dead-code --no-dead-stores `
        -r $ReferenceDirectory -o $OutputDirectory $Assembly
    if ($LASTEXITCODE -ne 0) {
        throw "ILSpy failed for $Assembly with exit code $LASTEXITCODE."
    }
    $source = @(Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.cs' -File)
    if ($source.Count -ne 1) {
        throw "Expected one decompiled source file for $Assembly, found $($source.Count)."
    }
    $source[0].FullName
}

function Measure-Pattern([string] $Path, [string] $Pattern) {
    $sum = (Select-String -LiteralPath $Path -Pattern $Pattern -AllMatches |
        ForEach-Object { $_.Matches.Count } | Measure-Object -Sum).Sum
    if ($null -eq $sum) { return 0 }
    [int] $sum
}

try {
    $losslessSource = Invoke-Decompile $LosslessAssembly $losslessDirectory
    $optimizedSource = Invoke-Decompile $OptimizedAssembly $optimizedDirectory
    $patterns = [ordered]@{
        MathAbs = 'Math\.Abs\('
        Switch = 'switch \('
        InfiniteLoop = 'while \(true\)'
        IlGoto = 'goto IL_'
    }
    $measurements = [ordered]@{}
    foreach ($entry in $patterns.GetEnumerator()) {
        $measurements[$entry.Key] = [pscustomobject]@{
            Lossless = Measure-Pattern $losslessSource $entry.Value
            Optimized = Measure-Pattern $optimizedSource $entry.Value
        }
    }

    foreach ($entry in $measurements.GetEnumerator()) {
        Write-Host ("{0}: lossless={1}, optimized={2}" -f `
            $entry.Key, $entry.Value.Lossless, $entry.Value.Optimized)
    }

    $errors = [Collections.Generic.List[string]]::new()
    if ($measurements.MathAbs.Optimized -ne 0) {
        $errors.Add("Optimized output still contains Math.Abs dispatcher scaffolding.")
    }
    if (($measurements.Switch.Lossless - $measurements.Switch.Optimized) -lt 41) {
        $errors.Add("Fewer than 41 dispatcher switches disappeared.")
    }
    if ($measurements.Switch.Optimized -ne 5) {
        $errors.Add("The audited five domain switches changed.")
    }
    # Strict EH SSA keeps the two enumerator conditions in the loop body so the
    # CLI finally regions remain exact. ILSpy renders those legitimate loops as
    # while(true) + break instead of while(MoveNext()). They are not dispatchers:
    # the independent Math.Abs, switch-removal and IL-label gates below/above
    # continue to reject dispatcher scaffolding.
    if ($measurements.InfiniteLoop.Optimized -gt 13) {
        $errors.Add("Optimized output has more than 13 real while(true) loops.")
    }
    if ($measurements.IlGoto.Optimized -ne 0) {
        $errors.Add("Optimized output still contains decompiler IL-label gotos.")
    }
    if ($errors.Count -gt 0) {
        throw ($errors -join ' ')
    }
    Write-Host 'ILSpy sample1 control-flow quality gate passed.'
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        $resolvedWork = [IO.Path]::GetFullPath($workRoot)
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedWork.StartsWith($resolvedTemp,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to delete ILSpy audit directory outside the temp root: $resolvedWork"
        }
        [IO.Directory]::Delete($resolvedWork, $true)
    }
}
