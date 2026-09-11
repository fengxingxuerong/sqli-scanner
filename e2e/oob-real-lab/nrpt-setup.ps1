# nrpt-setup.ps1 —— 提权 NRPT 管理（v2：带日志落盘，便于普通会话读取结果）
# NRPT 增删需要管理员权限；本脚本须经 -Verb RunAs 运行
$ErrorActionPreference = 'Continue'
$log = 'D:\projects\sqli-scanner\e2e\oob-real-lab\nrpt-setup.log'
"=== nrpt-setup start $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

# 1) 移除历史实验遗留（.oob-lab.local 是 mDNS 保留后缀，单播 NRPT 不生效）
Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Namespace -like '*oob-lab*' } | ForEach-Object {
  try {
    Remove-DnsClientNrptRule -Namespace $_.Namespace -Force -ErrorAction Stop
    "removed: $($_.Namespace)" | Out-File $log -Append -Encoding utf8
  } catch {
    "remove-fail [$($_.Namespace)]: $($_.Exception.Message)" | Out-File $log -Append -Encoding utf8
  }
}

# 2) 添加新命名空间（.test 保留 TLD 无 mDNS 特殊处理，单播 DNS 走 NRPT）
try {
  Add-DnsClientNrptRule -Namespace '.ooblab.test' -NameServers '127.0.0.1' -ErrorAction Stop
  "added: .ooblab.test -> 127.0.0.1" | Out-File $log -Append -Encoding utf8
} catch {
  "add-fail: $($_.Exception.Message)" | Out-File $log -Append -Encoding utf8
}

ipconfig /flushdns | Out-Null
Get-DnsClientNrptRule -ErrorAction SilentlyContinue | ForEach-Object { "final: $($_.Namespace) => $($_.NameServers -join ',')" | Out-File $log -Append -Encoding utf8 }
"NRPT-SETUP-DONE" | Out-File $log -Append -Encoding utf8
