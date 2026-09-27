# One version of the recovery fixture manifest: every entry under -Root (long paths through \\?\),
# with the relative path ("/" separators, the root is not listed), kind, size, sha256, mtime (Unix ms
# and ISO UTC) and the Windows attributes the vault format restores (readonly = 1, hidden = 2).
#   fixture-manifest.ps1 -Root C:\bbtest\rfx\src -Out C:\bbtest\rfx\manifest-v1.json
param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$base = '\\?\' + (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$sha = [Security.Cryptography.SHA256]::Create()
$epochTicks = 621355968000000000
$entries = foreach ($e in Get-ChildItem -LiteralPath $base -Recurse -Force) {
  $rel = $e.FullName.Substring($base.Length + 1).Replace('\', '/')
  $bits = 0
  if ($e.Attributes -band [IO.FileAttributes]::ReadOnly) { $bits = $bits -bor 1 }
  if ($e.Attributes -band [IO.FileAttributes]::Hidden) { $bits = $bits -bor 2 }
  $names = @(); if ($bits -band 1) { $names += 'readonly' }; if ($bits -band 2) { $names += 'hidden' }
  $ms = [int64][math]::Floor(($e.LastWriteTimeUtc.Ticks - $epochTicks) / 10000)
  $o = [ordered]@{ path = $rel; kind = $(if ($e.PSIsContainer) { 'dir' } else { 'file' }) }
  if (-not $e.PSIsContainer) {
    $o.size = $e.Length
    $fs = [IO.File]::OpenRead($e.FullName); try { $o.sha256 = ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '' } finally { $fs.Dispose() }
  }
  $o.mtime_ms = $ms
  $o.mtime = $e.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $o.attributes = $names
  $o.attr = $bits
  [pscustomobject]$o
}
$list = New-Object 'System.Collections.Generic.List[object]'
foreach ($x in $entries) { $list.Add($x) }
$list.Sort([Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.path, $b.path) })
$entries = $list.ToArray()
# ConvertTo-Json in Windows PowerShell 5.1 writes one-element arrays as arrays only inside objects,
# so attributes stay arrays; write UTF-8 without a BOM.
$json = ConvertTo-Json -InputObject $entries -Depth 5
[IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding($false)))
"$($entries.Count) entries ($(@($entries | Where-Object kind -eq 'file').Count) files, $(@($entries | Where-Object kind -eq 'dir').Count) folders) -> $Out"
