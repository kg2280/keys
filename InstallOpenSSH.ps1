# Define paths
$folderPath = "C:\"
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.3.0p2-Preview/OpenSSH-Win64.zip"
$zipFile = "C:\temp\OpenSSH-Win64.zip"
$user = "C:\Users\Helpox"
$sshd_config_URL = "https://raw.githubusercontent.com/kg2280/keys/refs/heads/master/sshd_config"
$sshd_config_path = "C:\ProgramData\ssh\sshd_config"

# Download the ZIP file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile

# Extract the ZIP file
Expand-Archive -Path $zipFile -DestinationPath $folderPath -Force

# Optional: Delete the ZIP file after extraction
Remove-Item $zipFile

# Run install script
Set-Location "C:\OpenSSH-Win64"
.\install-sshd.ps1

## Install config file
Invoke-WebRequest -Uri $sshd_config_Url -OutFile $sshd_config_path


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
$url = "https://raw.githubusercontent.com/kg2280/keys/refs/heads/master/id_rsa.pub"
$authorizedKey = Invoke-WebRequest $url
New-Item -Force -ItemType Directory -Path $user\.ssh; Add-Content -Force -Path $user\.ssh\authorized_keys -Value "$authorizedKey"

# Repair permission
.\FixHostFilePermissions.ps1
.\FixUserFilePermissions.ps1

