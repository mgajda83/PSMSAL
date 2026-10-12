Get-ChildItem -Path $PSScriptRoot | Unblock-File
Get-ChildItem -Path $PSScriptRoot\*.ps1 -Recurse | Foreach-Object{ . $_.FullName }

Import-Module $PSScriptRoot\PSMSAL.dll

Export-ModuleMember -Cmdlet Get-PSMSALToken -Function *
