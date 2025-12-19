<#

NOTE: THIS IS DANGEROUS BE CAREFUL
You must run PowerShell as Administrator
Selecting the wrong disk can destroy data
This copies unused space, deleted data, slack space, and errors
The destination must have free space ≥ source disk size
This is forensic-style imaging, not backup software
Before running this:
Get-Disk | Format-Table Number, FriendlyName, SerialNumber, Size
.SYNOPSIS
  Forensic-style raw disk imaging (sector-by-sector) with logging, resume, hashing, verification, and sparse image support.

.DESCRIPTION
  Acquisition:
    - Reads \\.\PhysicalDriveN and writes a raw .img
    - Logs read errors (bad sectors / IO errors) and fills unreadable blocks with 0x00 to preserve offsets
    - Supports resume from an existing partial image (continues from its current length)
    - Computes SHA256 during acquisition; if resuming, re-hashes existing bytes first

  Verification (read-only):
    - Verifies SHA256 of image matches the saved manifest
    - Optional: verifies image matches source disk byte-for-byte (read-only)

.PARAMETER Mode
  Acquire or Verify

.PARAMETER DiskNumber
  Physical disk number (from Get-Disk)

.PARAMETER ImagePath
  Output image path (.img)

.PARAMETER BlockSizeMB
  Block size in MB (default 4). Large values are faster, smaller values can be gentler on marginal disks.

.PARAMETER Resume
  Resume from existing image file length.

.PARAMETER Sparse
  Make destination file sparse and skip physically writing all-zero blocks (logical bytes remain correct).

.PARAMETER LogPath
  CSV log for read errors

.PARAMETER ManifestPath
  JSON manifest storing imaging metadata and SHA256

.PARAMETER VerifyAgainstSource
  In Verify mode, also compare image vs disk byte-for-byte (slow).

.EXAMPLE
  # Identify disks:
  Get-Disk | ft Number,FriendlyName,SerialNumber,Size

  # Acquire (new image)
  .\Invoke-ForensicDiskImage.ps1 -Mode Acquire -DiskNumber 1 -ImagePath D:\Images\disk1.img

  # Acquire with resume + sparse
  .\Invoke-ForensicDiskImage.ps1 -Mode Acquire -DiskNumber 1 -ImagePath D:\Images\disk1.img -Resume -Sparse

  # Verify hash only
  .\Invoke-ForensicDiskImage.ps1 -Mode Verify -DiskNumber 1 -ImagePath D:\Images\disk1.img

  # Verify hash + verify against source disk (read-only, slow)
  .\Invoke-ForensicDiskImage.ps1 -Mode Verify -DiskNumber 1 -ImagePath D:\Images\disk1.img -VerifyAgainstSource
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('Acquire','Verify')]
  [string]$Mode,

  [Parameter(Mandatory)]
  [ValidateRange(0, 128)]
  [int]$DiskNumber,

  [Parameter(Mandatory)]
  [string]$ImagePath,

  [ValidateRange(1, 256)]
  [int]$BlockSizeMB = 4,

  [switch]$Resume,
  [switch]$Sparse,

  [string]$LogPath = "",
  [string]$ManifestPath = "",

  [switch]$VerifyAgainstSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
  if (-not (Test-IsAdmin)) {
    throw "This script must be run as Administrator."
  }
}

function Ensure-Dir([string]$path) {
  $dir = Split-Path -Parent $path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

function Get-DiskInfo([int]$num) {
  $d = Get-Disk -Number $num -ErrorAction Stop
  [PSCustomObject]@{
    Number            = $d.Number
    FriendlyName      = $d.FriendlyName
    SerialNumber      = $d.SerialNumber
    Size              = [int64]$d.Size
    LogicalSectorSize = [int]$d.LogicalSectorSize
    PhysicalSectorSize= [int]$d.PhysicalSectorSize
    BusType           = $d.BusType
    PartitionStyle    = $d.PartitionStyle
  }
}

function Write-ErrorLogHeader([string]$path) {
  if (-not (Test-Path $path)) {
    "Timestamp,DiskNumber,OffsetBytes,LengthBytes,Action,Message" | Out-File -FilePath $path -Encoding UTF8
  }
}

function Log-ReadError {
  param(
    [string]$Path,
    [int]$DiskNumber,
    [int64]$Offset,
    [int]$Length,
    [string]$Action,
    [string]$Message
  )
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = ('"{0}",{1},{2},{3},"{4}","{5}"' -f $ts,$DiskNumber,$Offset,$Length,$Action,($Message -replace '"',''''))
  Add-Content -Path $Path -Value $line -Encoding UTF8
}

function Enable-SparseFile([string]$path) {
  # Uses fsutil; works on NTFS/ReFS. If it fails, we continue without sparse.
  try {
    & fsutil sparse setflag "$path" | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Buffer-IsAllZero([byte[]]$buf, [int]$count) {
  for ($i=0; $i -lt $count; $i++) {
    if ($buf[$i] -ne 0) { return $false }
  }
  return $true
}

function New-ManifestObject {
  param(
    [object]$DiskInfo,
    [string]$ImagePath,
    [string]$Mode,
    [int]$BlockSizeBytes,
    [bool]$Sparse
  )
  [PSCustomObject]@{
    schemaVersion   = 1
    createdLocal    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    mode
