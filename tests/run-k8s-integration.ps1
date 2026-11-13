$ErrorActionPreference = "Stop"

$Namespace = "webshield"
$LocalPort = 18081
$BaseUrl = "http://127.0.0.1:$LocalPort"

$StdOutFile = Join-Path $PSScriptRoot "port-forward.stdout.log"
$StdErrFile = Join-Path $PSScriptRoot "port-forward.stderr.log"

$portForwardProcess = $null
$testExitCode = 1


Write-Host "============================================"
Write-Host "WebShield Kubernetes Integration Test"
Write-Host "============================================"
Write-Host "Namespace: $Namespace"
Write-Host "Local URL: $BaseUrl"
Write-Host ""


try {

    # ==================================================
    # Remove previous logs
    # ==================================================

    Remove-Item $StdOutFile -Force -ErrorAction SilentlyContinue
    Remove-Item $StdErrFile -Force -ErrorAction SilentlyContinue


    # ==================================================
    # Verify Kubernetes Deployment
    # ==================================================

    Write-Host "Checking Kubernetes deployment..."

    kubectl get pods -n $Namespace

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to access Kubernetes namespace."
    }


    # ==================================================
    # Start Temporary Port Forward
    # ==================================================

    Write-Host ""
    Write-Host "Starting temporary port-forward..."

    $portForwardProcess = Start-Process `
        -FilePath "kubectl" `
        -ArgumentList @(
            "port-forward",
            "service/web",
            "${LocalPort}:80",
            "-n",
            $Namespace
        ) `
        -RedirectStandardOutput $StdOutFile `
        -RedirectStandardError $StdErrFile `
        -WindowStyle Hidden `
        -PassThru


    Write-Host "kubectl PID: $($portForwardProcess.Id)"


    # ==================================================
    # Wait Until WebShield Is Reachable
    # ==================================================

    $ready = $false

    for ($attempt = 1; $attempt -le 40; $attempt++) {

        Start-Sleep -Seconds 1

        if ($portForwardProcess.HasExited) {
            throw "kubectl port-forward exited unexpectedly."
        }


        try {

            $response = Invoke-WebRequest `
                -Uri "$BaseUrl/api/health" `
                -UseBasicParsing `
                -TimeoutSec 3


            if ($response.StatusCode -eq 200) {

                $ready = $true

                Write-Host ""
                Write-Host "WebShield became reachable after $attempt second(s)."

                break
            }

        } catch {

            Write-Host "Waiting for WebShield... attempt $attempt/40"

        }
    }


    if (-not $ready) {
        throw "WebShield did not become reachable through Kubernetes port-forward."
    }


    # ==================================================
    # Run Integration Test
    # ==================================================

    Write-Host ""
    Write-Host "Running full integration test..."
    Write-Host ""

    $env:BASE_URL = $BaseUrl


    node --test tests/api.integration.test.mjs


    $testExitCode = $LASTEXITCODE


    if ($testExitCode -ne 0) {
        throw "Integration tests failed with exit code $testExitCode."
    }


    Write-Host ""
    Write-Host "============================================"
    Write-Host "Integration Test Successful"
    Write-Host "============================================"


} catch {

    Write-Host ""
    Write-Host "============================================"
    Write-Host "Integration Test Failed"
    Write-Host "============================================"

    Write-Host $_.Exception.Message


    if (Test-Path $StdOutFile) {

        Write-Host ""
        Write-Host "--- kubectl port-forward stdout ---"

        Get-Content $StdOutFile
    }


    if (Test-Path $StdErrFile) {

        Write-Host ""
        Write-Host "--- kubectl port-forward stderr ---"

        Get-Content $StdErrFile
    }


    $testExitCode = 1

} finally {

    # ==================================================
    # Cleanup Port Forward
    # ==================================================

    if ($portForwardProcess) {

        if (-not $portForwardProcess.HasExited) {

            Write-Host ""
            Write-Host "Stopping temporary port-forward..."

            Stop-Process `
                -Id $portForwardProcess.Id `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }


    Remove-Item Env:BASE_URL `
        -ErrorAction SilentlyContinue
}


exit $testExitCode