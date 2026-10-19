<#
.SYNOPSIS
    Bypasses Windows 11 In-place Upgrade "Host Is Newer" (CHostIsNewerChecker) HardBlock.
.DESCRIPTION
    Patches setupcompat.dll to bypass the kernel version comparison check (Host OS Build > Target OS Build),
    allowing "Keep personal files and apps" during in-place upgrade/downgrade.
.PARAMETER SetupPath
    Path to the extracted Windows 11 installation media (folder containing setup.exe and sources/).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SetupPath = "."
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 SetupCompat In-Place Upgrade Bypass Tool     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Locate setupcompat.dll
$candidate = Join-Path $SetupPath "sources\setupcompat.dll"
if (-not (Test-Path $candidate)) {
    $candidate = Join-Path $SetupPath "setupcompat.dll"
}

if (-not (Test-Path $candidate)) {
    Write-Error "Could not find setupcompat.dll in '$SetupPath' or '$SetupPath\sources'."
    exit 1
}

$dllPath = (Resolve-Path $candidate).Path
$backupPath = "$dllPath.bak"

Write-Host "Target DLL: $dllPath" -ForegroundColor Yellow

# Create backup if not already present
if (-not (Test-Path $backupPath)) {
    Copy-Item -Path $dllPath -Destination $backupPath -Force
    Write-Host "[+] Backup created: $backupPath" -ForegroundColor Green
} else {
    Write-Host "[*] Backup already exists: $backupPath" -ForegroundColor Gray
}

# Remove Read-Only attribute if present
$item = Get-Item $dllPath
if ($item.IsReadOnly) {
    $item.IsReadOnly = $false
    Write-Host "[+] Cleared Read-Only attribute." -ForegroundColor Green
}

$bytes = [System.IO.File]::ReadAllBytes($dllPath)

# Patch 1: ConX::Compatibility::CSystemAbstraction::HostIsNewer
# Offset 0x25B10: call CompareVersions (E8 EF D1 FD FF) -> xor eax, eax; nop; nop; nop (31 C0 90 90 90)
$p1_off = 0x25B10
$p1_orig = @(0xE8, 0xEF, 0xD1, 0xFD, 0xFF)
$p1_patch = @(0x31, 0xC0, 0x90, 0x90, 0x90)

# Patch 2: CHostIsNewerChecker::Execute
# Offset 0x10714: jz 0x107CE (0F 84 B4 00 00 00) -> jmp 0x107CE; nop (E9 B5 00 00 00 90)
$p2_off = 0x10714
$p2_orig = @(0x0F, 0x84, 0xB4, 0x00, 0x00, 0x00)
$p2_patch = @(0xE9, 0xB5, 0x00, 0x00, 0x00, 0x90)

Write-Host "[*] Checking signature bytes..." -ForegroundColor Yellow

$match1 = $true
for ($i = 0; $i -lt $p1_orig.Length; $i++) {
    if ($bytes[$p1_off + $i] -ne $p1_orig[$i]) { $match1 = $false; break }
}

$match2 = $true
for ($i = 0; $i -lt $p2_orig.Length; $i++) {
    if ($bytes[$p2_off + $i] -ne $p2_orig[$i]) { $match2 = $false; break }
}

if (-not $match1 -or -not $match2) {
    # Check if already patched
    $alreadyPatched = $true
    for ($i = 0; $i -lt $p1_patch.Length; $i++) {
        if ($bytes[$p1_off + $i] -ne $p1_patch[$i]) { $alreadyPatched = $false; break }
    }
    if ($alreadyPatched) {
        Write-Host "[!] setupcompat.dll is ALREADY patched!" -ForegroundColor Green
        exit 0
    }

    Write-Error "Signature mismatch at target offsets. This file might be from an unsupported build version of Windows Setup."
    exit 1
}

# Apply Patch 1
for ($i = 0; $i -lt $p1_patch.Length; $i++) {
    $bytes[$p1_off + $i] = $p1_patch[$i]
}

# Apply Patch 2
for ($i = 0; $i -lt $p2_patch.Length; $i++) {
    $bytes[$p2_off + $i] = $p2_patch[$i]
}

# Save patched file
[System.IO.File]::WriteAllBytes($dllPath, $bytes)
Write-Host "[+] Successfully patched setupcompat.dll!" -ForegroundColor Green
Write-Host "    - Offset 0x25B10: 31 C0 90 90 90 (Force HostIsNewer = false)"
Write-Host "    - Offset 0x10714: E9 B5 00 00 00 90 (Force CHostIsNewerChecker = NoIssue)"

Write-Host "`nReady to launch setup. Run: setup.exe /DynamicUpdate Disable" -ForegroundColor Cyan
