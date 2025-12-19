<#
.SYNOPSIS
  Extracts common network configuration from the Windows Registry and displays it in readable form.

.NOTES
  - Registry does not always contain "effective" runtime config (DHCP leases, current routes, etc.).
  - This script focuses on network-related registry configuration: adapters, TCP/IP interfaces, profiles, DNS policy.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Format-Value {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    # Handle common registry types
    if ($Value -is [string[]]) {
        return ($Value -join ', ')
    }
    if ($Value -is [byte[]]) {
        return ($Value | ForEach-Object { $_.ToString('X2') }) -join ' '
    }
    return $Value
}

function Get-RegPropsSafe {
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        # Remove PS metadata properties
        $props = $item.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS(.*)$' } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name  = $_.Name
                    Value = (Format-Value $_.Value)
                }
            }
        return $props
    } catch {
        return @()
    }
}

function Try-GetRegValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try {
        (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name
    } catch {
        $null
    }
}

function Convert-Category {
    param([int]$Category)
    switch ($Category) {
        0 { "Public" }
        1 { "Private" }
        2 { "DomainAuthenticated" }
        default { "Unknown($Category)" }
    }
}

Write-Host "=== Network Registry Summary ===" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "User:     $env:USERNAME"
Write-Host ""

# --- 1) Adapters (Class GUID for Network Adapters)
$adapterClass = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'

Write-Host "=== Adapters (Registry Class) ===" -ForegroundColor Cyan
if (Test-Path $adapterClass) {
    $adapterKeys = Get-ChildItem -Path $adapterClass -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^\d{4}$' } |
        Sort-Object { [int]$_.PSChildName }

    foreach ($k in $adapterKeys) {
        $p = "Registry::$($k.Name)"
        $desc   = Try-GetRegValue -Path $p -Name 'DriverDesc'
        $netCfg = Try-GetRegValue -Path $p -Name 'NetCfgInstanceId'   # Interface GUID (often maps to TCP/IP interface key)
        $svc    = Try-GetRegValue -Path $p -Name 'Service'
        $mfg    = Try-GetRegValue -Path $p -Name 'Manufacturer'

        # Skip empty placeholder entries
        if (-not $desc -and -not $netCfg -and -not $svc) { continue }

        Write-Host ""
        Write-Host "Adapter Key: $($k.PSChildName)" -ForegroundColor Yellow
        if ($desc) { Write-Host "  Name:              $desc" }
        if ($mfg)  { Write-Host "  Manufacturer:      $mfg" }
        if ($svc)  { Write-Host "  Service:           $svc" }
        if ($netCfg){ Write-Host "  NetCfgInstanceId:  $netCfg" }
    }
} else {
    Write-Host "Adapter class key not found: $adapterClass"
}
Write-Host ""

# --- 2) TCP/IP Interfaces (IPv4)
$tcpipIfBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
Write-Host "=== TCP/IP Interfaces (IPv4) ===" -ForegroundColor Cyan
if (Test-Path $tcpipIfBase) {
    $ifKeys = Get-ChildItem -Path $tcpipIfBase -ErrorAction SilentlyContinue
    foreach ($k in $ifKeys) {
        $p = "Registry::$($k.Name)"
        $guid = $k.PSChildName

        $dhcpEnabled = Try-GetRegValue -Path $p -Name 'EnableDHCP'
        $ipAddr      = Try-GetRegValue -Path $p -Name 'IPAddress'
        $subnetMask  = Try-GetRegValue -Path $p -Name 'SubnetMask'
        $gateway     = Try-GetRegValue -Path $p -Name 'DefaultGateway'
        $dns         = Try-GetRegValue -Path $p -Name 'NameServer'
        $dhcpIp      = Try-GetRegValue -Path $p -Name 'DhcpIPAddress'
        $dhcpMask    = Try-GetRegValue -Path $p -Name 'DhcpSubnetMask'
        $dhcpGw      = Try-GetRegValue -Path $p -Name 'DhcpDefaultGateway'
        $dhcpDns     = Try-GetRegValue -Path $p -Name 'DhcpNameServer'
        $domain      = Try-GetRegValue -Path $p -Name 'Domain'
        $searchList  = Try-GetRegValue -Path $p -Name 'SearchList'
        $mtu         = Try-GetRegValue -Path $p -Name 'MTU'
        $hostname    = Try-GetRegValue -Path $p -Name 'HostName'

        # Only print interfaces with something set
        $hasSomething =
            $dhcpEnabled -ne $null -or $ipAddr -or $dhcpIp -or $gateway -or $dns -or $domain -or $searchList -or $mtu -or $hostname

        if (-not $hasSomething) { continue }

        Write-Host ""
        Write-Host "Interface GUID: $guid" -ForegroundColor Yellow
        if ($hostname)   { Write-Host "  HostName:          $(Format-Value $hostname)" }
        if ($domain)     { Write-Host "  Domain:            $(Format-Value $domain)" }
        if ($searchList) { Write-Host "  SearchList:        $(Format-Value $searchList)" }
        if ($mtu)        { Write-Host "  MTU:               $mtu" }

        if ($dhcpEnabled -ne $null) {
            $dhcpText = if ($dhcpEnabled -eq 1) { "Enabled" } else { "Disabled" }
            Write-Host "  DHCP:              $dhcpText"
        }

        if ($ipAddr)     { Write-Host "  Static IP:         $(Format-Value $ipAddr)" }
        if ($subnetMask) { Write-Host "  Static Mask:       $(Format-Value $subnetMask)" }
        if ($gateway)    { Write-Host "  Static Gateway:    $(Format-Value $gateway)" }
        if ($dns)        { Write-Host "  Static DNS:        $(Format-Value $dns)" }

        if ($dhcpIp)     { Write-Host "  DHCP IP:           $(Format-Value $dhcpIp)" }
        if ($dhcpMask)   { Write-Host "  DHCP Mask:         $(Format-Value $dhcpMask)" }
        if ($dhcpGw)     { Write-Host "  DHCP Gateway:      $(Format-Value $dhcpGw)" }
        if ($dhcpDns)    { Write-Host "  DHCP DNS:          $(Format-Value $dhcpDns)" }
    }
} else {
    Write-Host "TCP/IP interface key not found: $tcpipIfBase"
}
Write-Host ""

# --- 3) TCP/IP Interfaces (IPv6)
$tcpip6IfBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces'
Write-Host "=== TCP/IP Interfaces (IPv6) ===" -ForegroundColor Cyan
if (Test-Path $tcpip6IfBase) {
    $ifKeys6 = Get-ChildItem -Path $tcpip6IfBase -ErrorAction SilentlyContinue
    foreach ($k in $ifKeys6) {
        $p = "Registry::$($k.Name)"
        $guid = $k.PSChildName

        # Common IPv6 values (varies by build/config)
        $disabled = Try-GetRegValue -Path $p -Name 'DisabledComponents'
        $addr     = Try-GetRegValue -Path $p -Name 'IPAddress'
        $dns      = Try-GetRegValue -Path $p -Name 'NameServer'

        $hasSomething = ($disabled -ne $null) -or $addr -or $dns
        if (-not $hasSomething) { continue }

        Write-Host ""
        Write-Host "Interface GUID: $guid" -ForegroundColor Yellow
        if ($disabled -ne $null) { Write-Host "  DisabledComponents: $disabled" }
        if ($addr) { Write-Host "  IPv6 Address(es):   $(Format-Value $addr)" }
        if ($dns)  { Write-Host "  IPv6 DNS:           $(Format-Value $dns)" }
    }
} else {
    Write-Host "TCP/IP6 interface key not found: $tcpip6IfBase"
}
Write-Host ""

# --- 4) Network Profiles (friendly names)
$profilesBase = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
Write-Host "=== Network Profiles (NetworkList) ===" -ForegroundColor Cyan
if (Test-Path $profilesBase) {
    $profiles = Get-ChildItem -Path $profilesBase -ErrorAction SilentlyContinue
    foreach ($k in $profiles) {
        $p = "Registry::$($k.Name)"
        $name = Try-GetRegValue -Path $p -Name 'ProfileName'
        $desc = Try-GetRegValue -Path $p -Name 'Description'
        $cat  = Try-GetRegValue -Path $p -Name 'Category'
        $managed = Try-GetRegValue -Path $p -Name 'Managed'
        $created = Try-GetRegValue -Path $p -Name 'DateCreated'
        $lastCon = Try-GetRegValue -Path $p -Name 'DateLastConnected'

        if (-not $name -and -not $desc) { continue }

        Write-Host ""
        Write-Host "Profile: $($k.PSChildName)" -ForegroundColor Yellow
        if ($name) { Write-Host "  Name:           $name" }
        if ($desc) { Write-Host "  Description:    $desc" }
        if ($cat -ne $null) { Write-Host "  Category:       $(Convert-Category -Category $cat)" }
        if ($managed -ne $null) { Write-Host "  Managed:        $managed" }
        if ($created) { Write-Host "  DateCreated:    $(Format-Value $created)" }
        if ($lastCon) { Write-Host "  LastConnected:  $(Format-Value $lastCon)" }
    }
} else {
    Write-Host "NetworkList profiles key not found: $profilesBase"
}
Write-Host ""

# --- 5) DNS Client NRPT (Name Resolution Policy Table) if present
$nrptBase = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'
Write-Host "=== DNS Policy (NRPT) ===" -ForegroundColor Cyan
if (Test-Path $nrptBase) {
    $rules = Get-ChildItem -Path $nrptBase -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "NRPT key exists but no rules found."
    } else {
        foreach ($k in $rules) {
            $p = "Registry::$($k.Name)"
            $props = Get-RegPropsSafe -Path $p
            Write-Host ""
            Write-Host "Rule: $($k.PSChildName)" -ForegroundColor Yellow
            foreach ($row in $props) {
                if ($row.Value -ne $null -and "$($row.Value)".Length -gt 0) {
                    Write-Host ("  {0,-22} {1}" -f ($row.Name + ":"), $row.Value)
                }
            }
        }
    }
} else {
    Write-Host "NRPT policy key not found (this is normal on many systems)."
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
