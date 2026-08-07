$securedFault = Join-Path $repoRoot 'FaultCases\bin\Release\net48\Secured-fault\FaultCases.dll'
$securedFaultRuntime = Join-Path $repoRoot `
    'FaultCases\bin\Release\net48\Secured-fault\AgileDotNet.VMRuntime.dll'
$devirtFault = Invoke-Devirtualizer -Tool $tool `
    -InputAssembly $securedFault -RuntimeAssembly $securedFaultRuntime `
    -OutputAssembly (Join-Path $workRoot 'fault-devirt\FaultCases.dll') `
    -ExpectedTotal 1 -MinimumAccepted 1 -Label 'Agile.NET fault fixture'
$devirtFaultRuntime = Join-Path `
    ([System.IO.Path]::GetDirectoryName($devirtFault.AssemblyPath)) 'AgileDotNet.VMRuntime.dll'
if (-not (Test-Path -LiteralPath $devirtFaultRuntime)) {
    Write-Pass 'Fully devirtualized fault fixture is standalone.'
}
else {
    Write-Failure 'Fully devirtualized fault fixture still emitted its VM runtime.'
}

$protectedFaultRun = Invoke-ManagedExecutable (Join-Path $faultInvokerBuild 'FaultCasesInvoker.exe') `
    -CommandLine ('"{0}"' -f $securedFault)
$devirtFaultRun = Invoke-ManagedExecutable (Join-Path $faultInvokerBuild 'FaultCasesInvoker.exe') `
    -CommandLine ('"{0}"' -f $devirtFault.AssemblyPath)
$faultExpected = Normalize-Output $faultSourceRun.StdOut
if (-not $devirtFaultRun.TimedOut -and $devirtFaultRun.ExitCode -eq 0 `
    -and (Normalize-Output $devirtFaultRun.StdOut) -eq $faultExpected) {
    Write-Pass 'Standalone fault fixture matches source on normal and unwind paths.'
}
else {
    Write-Failure 'Fault fixture runtime equivalence failed.'
}
if ($protectedFaultRun.TimedOut -or $protectedFaultRun.ExitCode -ne 0) {
    Write-Note 'Protected fault input is not CLR-loadable because Agile.NET emitted a truncated ' +
               'native-resource directory; it is used as transformation input, not a runtime oracle.'
}
elseif ((Normalize-Output $protectedFaultRun.StdOut) -ne $faultExpected) {
    Write-Failure 'CLR-loadable protected fault fixture differs from its source oracle.'
}
