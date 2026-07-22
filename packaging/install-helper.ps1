# install-helper.ps1 — the PRIVILEGED half of the Windows web install
# (sysinstall_win.c runs this behind one UAC prompt; the mac twin is
# install-helper.sh). One job: the ".<tld>" DNS route — an NRPT rule steering
# the TLD's queries at the in-app resolver on 127.0.0.1 (:53; NRPT cannot
# carry a port). The CA trust is a user-store op done in-process, and :443
# needs nothing on Windows (no privileged ports) — webproxy binds it directly.
#
# Usage:  install-helper.ps1 install   <tld>
#         install-helper.ps1 uninstall <tld>
#         install-helper.ps1 status    <tld>     (no admin needed)
# Exit 0 = success. Idempotent both ways.
param(
    [Parameter(Mandatory = $true)][ValidateSet('install', 'uninstall', 'status')]
    [string]$Action,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]{1,32}$')]
    [string]$Tld
)

$ErrorActionPreference = 'Stop'
$ns  = ".$Tld"
$tag = "pepenet-$Tld"     # mirrors APP_PF_ANCHOR: the rule is found by comment

function Get-OurRules {
    Get-DnsClientNrptRule | Where-Object {
        $_.Comment -eq $tag -or ($_.Namespace -contains $ns)
    }
}

switch ($Action) {
    'status' {
        $have = @(Get-OurRules).Count -gt 0
        Write-Output "resolver=$(if ($have) { 1 } else { 0 })"
        exit 0
    }
    'install' {
        # replace-don't-stack: drop any stale twin first
        Get-OurRules | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
        Add-DnsClientNrptRule -Namespace $ns -NameServers '127.0.0.1' -Comment $tag | Out-Null
        Clear-DnsClientCache
        exit 0
    }
    'uninstall' {
        Get-OurRules | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
        Clear-DnsClientCache
        exit 0
    }
}
