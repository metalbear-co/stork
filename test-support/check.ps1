param([switch]$Portable)

$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    Invoke-Checked -Program cargo -Arguments @('fmt', '--all', '--', '--check')
    Invoke-Checked -Program rustfmt -Arguments @('--edition', '2024', '--check', 'test-support/harness.rs', 'test-support/fixture_events.rs', 'test-support/process.rs')
    Invoke-Checked -Program cargo -Arguments @('build', '--locked')
    Invoke-Checked -Program cargo -Arguments @('clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
    $previousRustdocFlags = $env:RUSTDOCFLAGS
    try {
        $env:RUSTDOCFLAGS = "$previousRustdocFlags -D warnings".Trim()
        Invoke-Checked -Program cargo -Arguments @('doc', '--locked', '-p', 'stork', '--no-deps')
    }
    finally {
        $env:RUSTDOCFLAGS = $previousRustdocFlags
    }
    if ($Portable) {
        # IAT does not use the build-specific startup LoadLibrary address exception.
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '-p', 'stork', '--lib', '--', '--test-threads=1', '--skip', 'strategy::load_library::tests')
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '-p', 'stork', '--test', 'harness', '--', '--test-threads=1')
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '-p', 'stork', '--test', 'import_table', '--test', 'gates', '--', '--test-threads=1')
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '-p', 'stork', '--test', 'real_targets', '_iat_', '--', '--test-threads=1', '--nocapture')
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '-p', 'stork', '--doc')
    }
    else {
        Invoke-Checked -Program cargo -Arguments @('test', '--locked', '--', '--test-threads=1', '--nocapture')
    }
}
finally {
    Pop-Location
}
