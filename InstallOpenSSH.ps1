# Define paths
$ConfirmPreference = 'None'
$folderPath = "C:\"
$sshd_config_path = "C:\ProgramData\ssh\sshd_config"
$sshd_config_URL = "https://raw.githubusercontent.com/kg2280/keys/refs/heads/master/sshd_config"
$url = "https://raw.githubusercontent.com/kg2280/keys/refs/heads/master/id_rsa.pub"
$user = "C:\Users\Helpox"
$user2 = "C:\Users\Administrator"
$zipFile = "C:\Temp\OpenSSH-Win64.zip"
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.3.0p2-Preview/OpenSSH-Win64.zip"


if (-not (Test-Path -Path "C:\Temp" -PathType Container)) {
    New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
}

# Download the ZIP file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile

# Extract the ZIP file
Expand-Archive -Path $zipFile -DestinationPath $folderPath -Force

# Optional: Delete the ZIP file after extraction
Remove-Item $zipFile

# Run install script
Set-Location "C:\OpenSSH-Win64"
.\install-sshd.ps1

# Start the sshd service
Start-Service sshd

# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}


# Get my public key installed for user helpox.
$authorizedKey = Invoke-WebRequest $url -UseBasicParsing
New-Item -Force -ItemType Directory -Path $user\.ssh; Add-Content -Force -Path $user\.ssh\authorized_keys -Value "$authorizedKey"
New-Item -Force -ItemType Directory -Path $user2\.ssh; Add-Content -Force -Path $user2\.ssh\authorized_keys -Value "$authorizedKey"

## Install config file
Invoke-WebRequest -Uri $sshd_config_Url -OutFile $sshd_config_path
Restart-Service sshd

# Repair permission
.\FixHostFilePermissions.ps1 -Confirm:$false
.\FixUserFilePermissions.ps1 -Confirm:$false

