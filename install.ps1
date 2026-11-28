# Snare install script for Windows
# Usage: irm https://snare.sh/install.ps1 | iex
& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $repo = 'peg/snare'
  $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $arch = switch ($cpu) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "Unsupported architecture: $cpu" }
  }
  $dir = if ($env:SNARE_INSTALL_DIR) { $env:SNARE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\snare' }
  $dir = [IO.Path]::GetFullPath($dir)

  $tag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
  if ($tag -notmatch '^v\d+\.\d+\.\d+$') { throw "Unexpected release tag: $tag" }

  $zip = "snare_windows_$arch.zip"
  $base = "https://github.com/$repo/releases/download/$tag"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmp | Out-Null

  try {
    Write-Host "Installing snare $tag (windows/$arch)..."
    Invoke-WebRequest "$base/$zip" -OutFile "$tmp\$zip" -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

    $pattern = '^([0-9a-f]{64})\s+' + [regex]::Escape($zip) + '$'
    $expected = Get-Content "$tmp\checksums.txt" | ForEach-Object { if ($_ -match $pattern) { $Matches[1] } } | Select-Object -First 1
    if (-not $expected) { throw "No checksum for $zip in checksums.txt" }
    $actual = (Get-FileHash "$tmp\$zip" -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw "Checksum mismatch for ${zip}: expected $expected, got $actual" }
    Write-Host "Checksum verified"

    Expand-Archive "$tmp\$zip" -DestinationPath "$tmp\x"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item "$tmp\x\snare.exe" (Join-Path $dir 'snare.exe') -Force
  } finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }

  $key = (Get-Item 'HKCU:\').OpenSubKey('Environment', $true)
  try {
    $userPath = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (($userPath -split ';') -notcontains $dir) {
      $newPath = if ($userPath) { "$userPath;$dir" } else { $dir }
      $key.SetValue('Path', $newPath, 'ExpandString')
      # A no-op user variable write broadcasts the change to new terminals.
      [Environment]::SetEnvironmentVariable('SNARE_PATH_REFRESH', '1', 'User')
      [Environment]::SetEnvironmentVariable('SNARE_PATH_REFRESH', $null, 'User')
      $env:Path = "$env:Path;$dir"
      Write-Host "Added $dir to your user PATH (open a new terminal to pick it up)"
    }
  } finally {
    $key.Close()
  }

  Write-Host "Installed to $(Join-Path $dir 'snare.exe')"
  Write-Host ""
  Write-Host "Get started:"
  Write-Host "  snare arm"
  Write-Host ""
  Write-Host "Docs: https://snare.sh"
}
