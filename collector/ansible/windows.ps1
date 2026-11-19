# Collector is invoked by ansible.windows.win_powershell on a Windows target.
# Only read-only OS CIM, installed-software registry and Get-HotFix queries.
# Avoid Win32_Product (can trigger MSI consistency checks / repairs).

$Ansible.Changed = $false
$ErrorActionPreference = 'Stop'

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$hotfixes = @(Get-HotFix | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.HotFixID)
} | ForEach-Object { [string]$_.HotFixID })

$packages = @{}
$uninstallPaths = @(
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($regPath in $uninstallPaths) {
    $entries = @(Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue)
    foreach ($entry in $entries) {
        $name = [string]$entry.DisplayName
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name.Length -gt 180) { continue }

        $version = [string]$entry.DisplayVersion
        if ($version.Length -gt 120) { $version = $version.Substring(0, 120) }
        if (-not $packages.ContainsKey($name)) { $packages[$name] = @() }
        $packages[$name] += @{
            name = $name
            version = $version
            source = 'windows_registry'
        }
    }
}

$Ansible.Result = @{
    ansible_facts = @{
        ansible_os_family = 'Windows'
        ansible_distribution = [string]$os.Caption
        ansible_distribution_version = [string]$os.Version
        os_build = [string]$os.BuildNumber
        packages = $packages
        windows_kb = $hotfixes
    }
}
