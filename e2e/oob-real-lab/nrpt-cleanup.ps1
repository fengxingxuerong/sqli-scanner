$ErrorActionPreference = 'Continue'
Start-Transcript -Path "$env:TEMP\nrpt-cleanup2.log" -Force
try {
  Get-DnsClientNrptRule | Where-Object { $_.Namespace -in @('.ooblab.test', '.oob-lab.local') } | Remove-DnsClientNrptRule -Force
  Write-Host 'Remaining rules:'
  Get-DnsClientNrptRule | ForEach-Object { Write-Host "  $($_.Namespace)" }
} catch {
  Write-Host "ERROR: $_"
}
Stop-Transcript
