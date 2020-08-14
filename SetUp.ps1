#PowerShell Install
Invoke-Expression "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"

#WINGET install
Invoke-WebRequest -Uri https://github.com/microsoft/winget-cli/releases/download/v0.1.4331-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle -OutFile Winget.appx -UseBasicParsing
Add-AppxPackage .\Winget.appx

#Install Applications
$Apps = "Google.Chrome","Notepad++","Battle.Net","Discord","Visual Studio Code","Steam","Git","Spotify","Nvidia.GeForceExperience"
$Apps | ForEach-Object {winget install $_ -e }

#https://www.google.com/drive/download/


#Remove Bloat
