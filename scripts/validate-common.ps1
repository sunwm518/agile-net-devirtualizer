function Write-Pass([string] $Message) {
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Failure([string] $Message) {
    $failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Note([string] $Message) {
    $notes.Add($Message)
    Write-Host "[NOTE] $Message" -ForegroundColor Yellow
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [switch] $AllowFailure
    )

    Push-Location $repoRoot
    try {
        $text = (& $FilePath @Arguments 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "Command failed ($exitCode): $FilePath $($Arguments -join ' ')`n$text"
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Output = $text
    }
}

function Invoke-ManagedExecutable {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $CommandLine = '',
        [int] $TimeoutSeconds = 20
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = [System.IO.Path]::GetFullPath($Path)
    $psi.Arguments = $CommandLine
    $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($psi.FileName)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) {
        throw "Could not start $Path"
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.WriteLine()
    $process.StandardInput.Close()

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { }
        return [pscustomobject]@{
            ExitCode = $null
            TimedOut = $true
            StdOut = $stdoutTask.Result
            StdErr = $stderrTask.Result
        }
    }

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        StdOut = $stdoutTask.Result
        StdErr = $stderrTask.Result
    }
}

function Normalize-Output([string] $Text) {
    (($Text -replace "`r`n", "`n") -replace "`r", "`n").Trim()
}

function Copy-DependencyDlls {
    param(
        [Parameter(Mandatory)] [string] $SourceDirectory,
        [Parameter(Mandatory)] [string] $DestinationDirectory,
        [string[]] $ExcludeNames = @()
    )

    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
        throw "Dependency directory does not exist: $SourceDirectory"
    }

    New-Item -ItemType Directory -Force -Path $DestinationDirectory | Out-Null
    # Native Curl dependencies may be hidden and its CA bundle is not a DLL. Keep the validation
    # directory runtime-complete instead of silently testing a reduced dependency set.
    foreach ($dependency in Get-ChildItem -LiteralPath $SourceDirectory -Force -File | Where-Object {
        $_.Extension -in @('.dll', '.crt')
    }) {
        if ($ExcludeNames -contains $dependency.Name) {
            continue
        }
        Copy-Item -LiteralPath $dependency.FullName `
            -Destination (Join-Path $DestinationDirectory $dependency.Name) -Force
    }
}

function Find-PEVerify {
    $command = Get-Command peverify.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $candidates = @(
        'C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\PEVerify.exe',
        'C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8.1 Tools\PEVerify.exe',
        'C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools\PEVerify.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Find-IlSpyEngineDirectory {
    $store = Join-Path $env:USERPROFILE '.dotnet\tools\.store\ilspycmd'
    if (-not (Test-Path -LiteralPath $store -PathType Container)) {
        return $null
    }
    $engine = Get-ChildItem -LiteralPath $store -Recurse `
        -Filter 'ICSharpCode.Decompiler.dll' -File -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($null -eq $engine) { return $null }
    $engine.DirectoryName
}

function Get-PEVerifyResult {
    param(
        [Parameter(Mandatory)] [string] $PEVerify,
        [Parameter(Mandatory)] [string] $AssemblyPath
    )

    $result = Invoke-Tool $PEVerify @($AssemblyPath, '/IL', '/MD', '/NOLOGO') -AllowFailure
    $errorCount = $null
    if ($result.Output -match 'All Classes and Methods .* Verified\.') {
        $errorCount = 0
    }
    elseif ($result.Output -match '(?m)^(\d+) Error\(s\) Verifying') {
        $errorCount = [int] $Matches[1]
    }

    [pscustomobject]@{
        ExitCode = $result.ExitCode
        ErrorCount = $errorCount
        Output = $result.Output
    }
}

function Invoke-Devirtualizer {
    param(
        [Parameter(Mandatory)] [string] $Tool,
        [Parameter(Mandatory)] [string] $InputAssembly,
        [Parameter(Mandatory)] [string] $RuntimeAssembly,
        [Parameter(Mandatory)] [string] $OutputAssembly,
        [Parameter(Mandatory)] [int] $ExpectedTotal,
        [Parameter(Mandatory)] [int] $MinimumAccepted,
        [Parameter(Mandatory)] [string] $Label,
        [string[]] $ExtraArguments = @()
    )

    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($OutputAssembly)) | Out-Null
    $arguments = @($Tool, $InputAssembly, $RuntimeAssembly, $OutputAssembly, '--show-failures') + $ExtraArguments
    $result = Invoke-Tool dotnet $arguments
    if ($result.Output -notmatch 'Devirtualized\s+(\d+)/(\d+)\s+method') {
        throw "Could not parse devirtualization result for $Label.`n$($result.Output)"
    }

    $accepted = [int] $Matches[1]
    $total = [int] $Matches[2]
    if ($total -ne $ExpectedTotal) {
        Write-Failure "$Label method total changed: $total, expected $ExpectedTotal."
    }
    elseif ($accepted -lt $MinimumAccepted) {
        Write-Failure "$Label builder acceptance regressed to $accepted/$total; floor is $MinimumAccepted/$ExpectedTotal."
    }
    else {
        Write-Pass "$Label builder acceptance: $accepted/$total (floor $MinimumAccepted/$ExpectedTotal)."
    }

    [pscustomobject]@{
        Accepted = $accepted
        Total = $total
        Output = $result.Output
        AssemblyPath = $OutputAssembly
    }
}
