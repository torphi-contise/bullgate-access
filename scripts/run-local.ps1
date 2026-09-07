[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int] $AccessPort = 5227,

    [ValidateRange(1, 65535)]
    [int] $PostgresPort = 5432
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$previousAccessPort = [Environment]::GetEnvironmentVariable('BULLGATE_ACCESS_PORT', 'Process')
$previousPostgresPort = [Environment]::GetEnvironmentVariable('BULLGATE_POSTGRES_PORT', 'Process')

try {
    [Environment]::SetEnvironmentVariable(
        'BULLGATE_ACCESS_PORT',
        $AccessPort.ToString(),
        'Process')
    [Environment]::SetEnvironmentVariable(
        'BULLGATE_POSTGRES_PORT',
        $PostgresPort.ToString(),
        'Process')

    Push-Location $repoRoot

    & docker compose up --detach --build access
    if ($LASTEXITCODE -ne 0) {
        throw "Nao foi possivel inicializar e iniciar o Bullgate Access."
    }

    & docker compose ps --all
    if ($LASTEXITCODE -ne 0) {
        throw "Nao foi possivel consultar os containers locais."
    }

    Write-Host "Bullgate Access local: http://localhost:$AccessPort"
    Write-Host "Liveness: http://localhost:$AccessPort/health/live"
    Write-Host 'Master key: volume bullgate-access-master-key. Integration credential: volume bullgate-access-integration.'
}
finally {
    [Environment]::SetEnvironmentVariable(
        'BULLGATE_ACCESS_PORT',
        $previousAccessPort,
        'Process')
    [Environment]::SetEnvironmentVariable(
        'BULLGATE_POSTGRES_PORT',
        $previousPostgresPort,
        'Process')

    if ((Get-Location).Path -eq $repoRoot) {
        Pop-Location
    }
}
