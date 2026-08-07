if (Test-Path -LiteralPath $methodQualityJson) {
    $methodQuality = Get-Content -LiteralPath $methodQualityJson -Raw | ConvertFrom-Json
    $methodQualityAssemblyHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $sample1Phi.AssemblyPath).Hash
    if ($methodQuality.summary.methods -eq 101 `
        -and $methodQuality.summary.decompiled -ge 95 `
        -and $methodQuality.sha256 -eq $methodQualityAssemblyHash `
        -and $methodQuality.summary.primaryDebt.'EH local/data-flow cleanup' -eq 9 `
        -and $methodQuality.summary.primaryDebt.'Managed-pointer lowering' -eq 7 `
        -and $methodQuality.summary.primaryDebt.'Exact type/materialization' -eq 8) {
        Write-Pass 'Per-method CIL/C# quality audit covers 101 methods and preserves the classified debt baseline.'
    }
    else {
        Write-Failure 'Per-method quality coverage or debt classification changed.'
    }
}
else {
    Write-Failure 'Per-method quality report was not generated.'
}
