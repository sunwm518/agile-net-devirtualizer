[CmdletBinding()]
param(
    [string] $OutputDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot 'FaultCases\bin\Release\net48'
}
else {
    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
}

$ilasmCandidates = @(
    'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe',
    'C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe'
)
$ilasm = $ilasmCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($null -eq $ilasm) {
    throw '.NET Framework 4.x ILAsm was not found.'
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$source = Join-Path $repoRoot 'FaultCases\FaultCases.il'
$output = Join-Path $OutputDirectory 'FaultCases.dll'
& $ilasm /DLL /QUIET "/OUTPUT=$output" $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
    throw "ILAsm failed with exit code $LASTEXITCODE."
}

Write-Output $output
