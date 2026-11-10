# Build self-update fixtures for Windows Sandbox validation (Gate 3).
# Runs on the HOST where Delphi compiler (dcc32/brcc32) and Python are available.
#
# Generates a throwaway ECDSA P-256 keypair outside the repository,
# compiles versioned launchers (1.0.0, 1.1.0, 1.2.0, 1.3.0-fail) with distinct
# version resources and the throwaway public key pinned under PORTAPPIX_TESTUPDATE,
# builds release zips, and signs releases.json feeds.

[CmdletBinding()]
param(
    [string]$StagingDir = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

if ([string]::IsNullOrWhiteSpace($StagingDir)) {
    $StagingDir = Join-Path $RepoRoot "tests\suite\fixtures\selfupdate"
}
$StagingDir = [System.IO.Path]::GetFullPath($StagingDir)

Write-Host "Self-update fixture builder"
Write-Host "  Repo root   : $RepoRoot"
Write-Host "  Staging dir : $StagingDir"

# 1. Check tools
$python = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command "py" -ErrorAction SilentlyContinue
}
if (-not $python) {
    throw "Python was not found on PATH. Required to generate throwaway keys and sign feeds."
}
$PythonExe = $python.Source

$dcc32 = Get-Command "dcc32.exe" -ErrorAction SilentlyContinue
if (-not $dcc32) {
    throw "dcc32.exe was not found on PATH. Open a Delphi command prompt."
}

$brcc32 = Get-Command "brcc32.exe" -ErrorAction SilentlyContinue
if (-not $brcc32) {
    throw "brcc32.exe was not found on PATH. Open a Delphi command prompt."
}

# Ensure icons resource exists
$IconsRes = Join-Path $RepoRoot "src\PortappixIcons.res"
if (-not (Test-Path $IconsRes)) {
    Write-Host "Compiling PortappixIcons.res..."
    & brcc32.exe (Join-Path $RepoRoot "src\PortappixIcons.rc") -fo $IconsRes | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to compile PortappixIcons.res"
    }
}

# 2. Generate throwaway signing key outside the repository
$TempKeyDir = Join-Path $env:TEMP ("portappix_selfupdate_key_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempKeyDir -Force | Out-Null
$PrivateKeyPem = Join-Path $TempKeyDir "key.pem"
$PublicKeyPem = Join-Path $TempKeyDir "public.pem"

Write-Host "Generating throwaway signing key in $TempKeyDir..."
& $PythonExe (Join-Path $RepoRoot "scripts\generate_signing_key.py") --out $PrivateKeyPem --public-out $PublicKeyPem --force-public | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "generate_signing_key.py failed with exit code $LASTEXITCODE"
}

# Extract CNG ECCPUBLICBLOB hex
$BlobHex = & $PythonExe -c @"
from cryptography.hazmat.primitives import serialization
import sys
key = serialization.load_pem_public_key(open(sys.argv[1], 'rb').read())
num = key.public_numbers()
print('4543533120000000' + num.x.to_bytes(32, 'big').hex().upper() + num.y.to_bytes(32, 'big').hex().upper())
"@ $PublicKeyPem

$BlobHex = $BlobHex.Trim()
if ($BlobHex.Length -ne 144) {
    throw "Invalid CNG public key hex length: $($BlobHex.Length)"
}
Write-Host "  CNG public key blob hex: $BlobHex"

$KeyIncPath = Join-Path $RepoRoot "src\PortappixTestKey.inc"
$OrigKeyIncContent = Get-Content $KeyIncPath -Raw

$TempBuildDir = Join-Path $env:TEMP ("portappix_selfupdate_build_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempBuildDir -Force | Out-Null

try {
    # Pin the throwaway public key in the build-time constant
    $NewKeyIncContent = @"
// Staged throwaway test public key for PORTAPPIX_TESTUPDATE
const
  TestPublicKeyHex = '$BlobHex';
"@
    Set-Content -Path $KeyIncPath -Value $NewKeyIncContent -NoNewline -Encoding utf8

    function Build-VersionedLauncher {
        param(
            [string]$Version,
            [string]$OutDir,
            [switch]$CrashOnStartup
        )

        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

        $Parts = $Version.Split('.')
        $Major = [int]$Parts[0]
        $Minor = [int]$Parts[1]
        $Patch = [int]$Parts[2]

        $RcPath = Join-Path $RepoRoot "src\LauncherVersion.rc"
        $ResPath = Join-Path $RepoRoot "src\LauncherVersion.res"

        $RcContent = @"
1 VERSIONINFO
FILEVERSION $Major,$Minor,$Patch,0
PRODUCTVERSION $Major,$Minor,$Patch,0
FILEOS 0x40004
FILETYPE 1
{
 BLOCK "StringFileInfo"
 {
  BLOCK "040904E4"
  {
   VALUE "FileVersion", "$Major.$Minor.$Patch.0"
   VALUE "ProductVersion", "$Major.$Minor.$Patch.0"
   VALUE "FileDescription", "Portappix Launcher Test Fixture $Version"
  }
 }
 BLOCK "VarFileInfo"
 {
  VALUE "Translation", 0x409, 1252
 }
}
"@
        Set-Content -Path $RcPath -Value $RcContent -Encoding ascii
        & brcc32.exe $RcPath -fo $ResPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to compile version resource for $Version"
        }

        $Defines = "-DPORTAPPIX_TESTUPDATE -DPORTAPPIX_VERSION_RES"
        if ($CrashOnStartup) {
            $Defines += " -DPORTAPPIX_CRASH_STARTUP"
        }

        $DprPath = Join-Path $RepoRoot "src\Launcher.dpr"
        Write-Host "  Building Launcher $Version (defines: $Defines)..."
        & dcc32.exe -B -Q -E"$OutDir" -N0"$OutDir" -Usrc -Isrc -Rsrc ($Defines.Split(' ')) "$DprPath" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "dcc32 failed building Launcher $Version"
        }

        $TargetExe = Join-Path $OutDir "Launcher.exe"
        if (-not (Test-Path $TargetExe)) {
            throw "Output executable not found: $TargetExe"
        }
        return $TargetExe
    }

    # Clean target staging dir
    if (Test-Path $StagingDir) {
        Remove-Item -Path $StagingDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

    $Dir100 = Join-Path $StagingDir "1.0.0"
    $Dir110 = Join-Path $StagingDir "1.1.0"
    $Dir120 = Join-Path $StagingDir "1.2.0"
    $Dir130Fail = Join-Path $StagingDir "1.3.0-fail"
    $FeedDir = Join-Path $StagingDir "feed"
    New-Item -ItemType Directory -Path $FeedDir -Force | Out-Null

    # Build 1.0.0, 1.1.0, 1.2.0, 1.3.0-fail
    Build-VersionedLauncher -Version "1.0.0" -OutDir $Dir100 | Out-Null
    Build-VersionedLauncher -Version "1.1.0" -OutDir $Dir110 | Out-Null
    Build-VersionedLauncher -Version "1.2.0" -OutDir $Dir120 | Out-Null
    Build-VersionedLauncher -Version "1.3.0" -OutDir $Dir130Fail -CrashOnStartup | Out-Null

    # Helper to package zip and create release json
    function Package-Release {
        param(
            [string]$Version,
            [string]$ExeDir,
            [string]$ZipName,
            [string]$FeedJsonName
        )

        $ZipPath = Join-Path $FeedDir $ZipName
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

        # Zip containing Launcher.exe at root
        $SourceExe = Join-Path $ExeDir "Launcher.exe"
        & $PythonExe -c @"
import zipfile, sys
with zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED) as z:
    z.write(sys.argv[2], 'Launcher.exe')
"@ $ZipPath $SourceExe

        $ZipBytes = [System.IO.File]::ReadAllBytes($ZipPath)
        $ZipSize = $ZipBytes.Length
        $ZipSha256 = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()

        $FeedJsonPath = Join-Path $FeedDir $FeedJsonName
        $JsonObj = [ordered]@{
            "schema"  = 1
            "channel" = "stable"
            "version" = $Version
            "url"     = "http://127.0.0.1:8080/$ZipName"
            "sha256"  = $ZipSha256
            "size"    = $ZipSize
            "notes"   = "Release $Version automated sandbox test fixture"
        }
        $JsonText = ($JsonObj | ConvertTo-Json -Depth 5).Replace("`r`n", "`n") + "`n"
        # Write exact LF bytes
        [System.IO.File]::WriteAllBytes($FeedJsonPath, [System.Text.Encoding]::UTF8.GetBytes($JsonText))

        # Sign with throwaway key
        $SigPath = "$FeedJsonPath.sig"
        & $PythonExe (Join-Path $RepoRoot "scripts\sign_catalog.py") --catalog $FeedJsonPath --key $PrivateKeyPem --public-key $PublicKeyPem --signature $SigPath
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to sign feed $FeedJsonPath"
        }
        Write-Host "  Packaged $ZipName and signed $FeedJsonName"
    }

    Package-Release -Version "1.1.0" -ExeDir $Dir110 -ZipName "portappix-1.1.0.zip" -FeedJsonName "releases-1.1.0.json"
    Package-Release -Version "1.2.0" -ExeDir $Dir120 -ZipName "portappix-1.2.0.zip" -FeedJsonName "releases-1.2.0.json"
    Package-Release -Version "1.3.0" -ExeDir $Dir130Fail -ZipName "portappix-1.3.0-fail.zip" -FeedJsonName "releases-1.3.0-fail.json"

    # Also copy public key pem to staging dir for reference / verification
    Copy-Item $PublicKeyPem (Join-Path $StagingDir "test_public.pem")

    Write-Host "Self-update fixture successfully built in $StagingDir"
}
finally {
    # Restore PortappixTestKey.inc
    Set-Content -Path $KeyIncPath -Value $OrigKeyIncContent -NoNewline -Encoding utf8
    Remove-Item (Join-Path $RepoRoot "src\LauncherVersion.*") -ErrorAction SilentlyContinue
    Remove-Item -Path $TempKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempBuildDir -Recurse -Force -ErrorAction SilentlyContinue
}
