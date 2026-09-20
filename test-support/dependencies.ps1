$ErrorActionPreference = 'Stop'

# Pinned official release; installation stays in ignored workspace build output.
$version = '0.20.2'
$package = "cargo-deny-$version-x86_64-pc-windows-msvc"
$checksum = '975a22143262fd27476d19ee00c7af67978426e40e1dee94eed6bbade1cf87dc'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $directory = Join-Path (Get-Location) 'target/tools'
    New-Item -ItemType Directory -Force $directory | Out-Null
    $archive = Join-Path $directory 'cargo-deny.tar.gz'
    if (-not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -UseBasicParsing "https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/$package.tar.gz" -OutFile $archive -TimeoutSec 60
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $checksum) {
        throw 'cargo-deny archive checksum mismatch'
    }
    & tar -xzf $archive -C $directory
    if ($LASTEXITCODE -ne 0) { throw 'cargo-deny extraction failed' }
    & (Join-Path $directory "$package/cargo-deny.exe") --locked check
    if ($LASTEXITCODE -ne 0) { throw 'dependency policy check failed' }
}
finally {
    Pop-Location
}
