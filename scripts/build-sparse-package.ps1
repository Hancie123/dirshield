<#
.SYNOPSIS
  Builds the signed sparse package that puts DirShield in the top-level
  Windows 11 File Explorer menu.

.DESCRIPTION
  Windows 11 only shows packaged IExplorerCommand handlers in its top-level
  menu, and only when the package is signed by a certificate the PC trusts
  (a code-signing certificate from a public CA, or Azure Trusted Signing).
  Without one, skip this script: the installer still adds the classic menu
  (under "Show more options").

  Steps:
    1. Build shell-ext (dirshield_shell.dll) with the certificate subject
       embedded as its package identity (shell-ext/build.rs).
    2. Fill in windows/sparse/AppxManifest.xml and pack it with the icons
       (makeappx /nv: dirshield.exe and the DLL live in the install folder,
       not in the package).
    3. Sign the package and the DLL (signtool, SHA-256, timestamped).
    4. Write target/sparse/tauri.sparse.conf.json, which adds both files to
       the installer: pass it to `tauri build --config`.

  Needs the Windows SDK (makeappx.exe, signtool.exe); GitHub's windows-latest
  runners have it.

.EXAMPLE
  ./scripts/build-sparse-package.ps1 -PfxPath codesign.pfx -PfxPassword $env:PFX_PASSWORD
  yarn tauri build --config src-tauri/target/sparse/tauri.sparse.conf.json
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $PfxPath,
  [string] $PfxPassword = '',
  [string] $PublisherDisplayName = 'Mero Vision Pvt. Ltd',
  [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$tauri = Join-Path $root 'src-tauri'
$out = Join-Path $tauri 'target\sparse'
$layout = Join-Path $out 'layout'
$msix = Join-Path $out 'dirshield-shell.msix'
$dll = Join-Path $tauri 'target\release\dirshield_shell.dll'

function Find-SdkTool([string] $name) {
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $tool = Get-ChildItem $kits -Directory -Filter '10.*' -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName "x64\$name" } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
  if (-not $tool) { throw "$name not found. Install the Windows 10/11 SDK." }
  $tool
}

function Invoke-Tool([string] $exe, [string[]] $arguments) {
  & $exe @arguments
  if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($exe)) failed with exit code $LASTEXITCODE" }
}

function ConvertTo-XmlText([string] $s) { [Security.SecurityElement]::Escape($s) }

# The package publisher must be exactly the certificate subject.
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $PfxPath).Path, $PfxPassword)
$publisher = $cert.Subject
Write-Host "Publisher: $publisher"

# Package versions have four parts.
$version = (Get-Content (Join-Path $tauri 'tauri.conf.json') -Raw | ConvertFrom-Json).version
$pkgVersion = (($version -split '[-+]')[0] + '.0')
Write-Host "Version:   $pkgVersion"

# 1. The handler DLL, with the package identity in its manifest.
$env:DIRSHIELD_SPARSE_PUBLISHER = $publisher
try {
  Invoke-Tool 'cargo' @('build', '--release', '-p', 'dirshield-shell', '--manifest-path', (Join-Path $tauri 'Cargo.toml'))
} finally {
  Remove-Item Env:DIRSHIELD_SPARSE_PUBLISHER
}

# 2. Package layout: manifest + icons.
if (Test-Path $layout) { Remove-Item $layout -Recurse -Force }
New-Item -ItemType Directory -Force (Join-Path $layout 'icons') | Out-Null
$manifest = (Get-Content (Join-Path $tauri 'windows\sparse\AppxManifest.xml') -Raw).
  Replace('{{PUBLISHER}}', (ConvertTo-XmlText $publisher)).
  Replace('{{PUBLISHER_DISPLAY_NAME}}', (ConvertTo-XmlText $PublisherDisplayName)).
  Replace('{{VERSION}}', $pkgVersion)
if ($manifest -match '\{\{') { throw 'AppxManifest.xml still has unfilled {{...}} values.' }
[IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $manifest, [Text.UTF8Encoding]::new($false))
foreach ($icon in 'StoreLogo.png', 'Square150x150Logo.png', 'Square44x44Logo.png') {
  Copy-Item (Join-Path $tauri "icons\$icon") (Join-Path $layout "icons\$icon")
}

$makeappx = Find-SdkTool 'makeappx.exe'
Invoke-Tool $makeappx @('pack', '/o', '/nv', '/d', $layout, '/p', $msix)

# 3. Sign. Windows won't register the package, or Explorer load the menu, otherwise.
$signtool = Find-SdkTool 'signtool.exe'
$sign = @('sign', '/fd', 'SHA256', '/f', (Resolve-Path $PfxPath).Path, '/tr', $TimestampUrl, '/td', 'SHA256')
if ($PfxPassword) { $sign += @('/p', $PfxPassword) }
Invoke-Tool $signtool ($sign + @($dll, $msix))

# 4. Installer resources (paths relative to src-tauri). Names must match
#    SPARSE_MSIX_FILE / HANDLER_DLL_FILE in src/platform/menu_spec.rs.
$conf = @{ bundle = @{ resources = @{
  'target/release/dirshield_shell.dll' = 'dirshield_shell.dll'
  'target/sparse/dirshield-shell.msix' = 'dirshield-shell.msix'
} } } | ConvertTo-Json -Depth 5
$confPath = Join-Path $out 'tauri.sparse.conf.json'
[IO.File]::WriteAllText($confPath, $conf, [Text.UTF8Encoding]::new($false))

Write-Host "Sparse package: $msix"
Write-Host "Tauri config:   $confPath"
