[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ImageRepository,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Tag
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dockerfile = Join-Path $repoRoot 'Dockerfile'
$image = "${ImageRepository}:$Tag"

& docker buildx build `
    --platform 'linux/arm64' `
    --file $dockerfile `
    --tag $image `
    --push `
    $repoRoot

if ($LASTEXITCODE -ne 0) {
    throw "Nao foi possivel construir e publicar $image."
}

Write-Host "Imagem ARM64 publicada: $image"
