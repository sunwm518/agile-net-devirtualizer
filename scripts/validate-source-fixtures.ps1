$sourceBuild = Join-Path $workRoot 'testcases-source'
Invoke-Tool dotnet @('build', 'TestCases\TestCases.csproj', '-c', $Configuration, '-o', $sourceBuild) | Out-Null
Write-Pass 'Known-source TestCases project builds cleanly.'

$invokerBuild = Join-Path $workRoot 'testcases-invoker'
Invoke-Tool dotnet @('build', 'TestCasesInvoker\TestCasesInvoker.csproj', '-c', $Configuration,
                     '-o', $invokerBuild) | Out-Null
Write-Pass 'Multi-input TestCases invoker builds cleanly.'

$functionPointerProbeBuild = Join-Path $workRoot 'function-pointer-probe'
Invoke-Tool dotnet @('build', 'tools\FunctionPointerProbe\FunctionPointerProbe.csproj',
                     '-c', $Configuration, '-o', $functionPointerProbeBuild) | Out-Null
Write-Pass 'Generic function-pointer runtime probe builds cleanly.'

$m5ProbeBuild = Join-Path $workRoot 'm5-probe'
Invoke-Tool dotnet @('build', 'tools\M5Probe\M5Probe.csproj',
                     '-c', $Configuration, '-o', $m5ProbeBuild) | Out-Null
Write-Pass 'Safe sample1 lifecycle probe builds cleanly.'

$controlFlowSourceRun = Invoke-ManagedExecutable (Join-Path $invokerBuild 'TestCasesInvoker.exe') `
    -CommandLine ('"{0}" --advanced-controlflow' -f (Join-Path $sourceBuild 'TestCases.exe'))
if ($controlFlowSourceRun.TimedOut -or $controlFlowSourceRun.ExitCode -ne 0) {
    Write-Failure "Known-source advanced control-flow matrix failed or timed out " +
                  "(exit $($controlFlowSourceRun.ExitCode)). $($controlFlowSourceRun.StdErr.Trim())"
}
else {
    Write-Pass 'Known-source advanced control-flow ground truth passes all 26 control-flow vectors.'
}

$faultSourceBuild = Join-Path $workRoot 'faultcases-source'
Invoke-Tool powershell.exe @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    'scripts\build-fault-fixture.ps1', '-OutputDirectory', $faultSourceBuild) | Out-Null
$faultInvokerBuild = Join-Path $workRoot 'faultcases-invoker'
Invoke-Tool dotnet @('build', 'FaultCasesInvoker\FaultCasesInvoker.csproj', '-c', $Configuration,
                     '-o', $faultInvokerBuild) | Out-Null
$faultSourceRun = Invoke-ManagedExecutable (Join-Path $faultInvokerBuild 'FaultCasesInvoker.exe') `
    -CommandLine ('"{0}"' -f (Join-Path $faultSourceBuild 'FaultCases.dll'))
if ($faultSourceRun.TimedOut -or $faultSourceRun.ExitCode -ne 0) {
    Write-Failure "Known-source fault matrix failed or timed out " +
                  "(exit $($faultSourceRun.ExitCode)). $($faultSourceRun.StdErr.Trim())"
}
else {
    Write-Pass 'Known-source ILAsm fault ground truth passes normal and exceptional paths.'
}

$extendedSourceRun = Invoke-ManagedExecutable (Join-Path $sourceBuild 'TestCases.exe') -CommandLine '--extended'
$expectedExtendedOutput = @(
    'Test4 (numeric comparisons): True',
    'Test5 (reference nulls): True',
    'Test6 (i4 arithmetic): 58'
)
if ($extendedSourceRun.TimedOut -or $extendedSourceRun.ExitCode -ne 0) {
    Write-Failure "Extended known-source TestCases failed or timed out (exit $($extendedSourceRun.ExitCode))."
}
else {
    $normalizedExtendedOutput = Normalize-Output $extendedSourceRun.StdOut
    $missingExtendedOutput = @($expectedExtendedOutput | Where-Object {
        $normalizedExtendedOutput -notmatch [regex]::Escape($_)
    })
    if ($missingExtendedOutput.Count -ne 0) {
        Write-Failure "Extended known-source TestCases output is missing: $($missingExtendedOutput -join '; ')"
    }
    else {
        Write-Pass 'Extended comparison/null/arithmetic ground truth passes for all three cases.'
    }
}
