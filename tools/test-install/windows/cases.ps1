# Runs on the test Windows machine (see run.sh): every installer case against the local server.
$ErrorActionPreference = "Continue"  # child stderr must not stop the run (PowerShell 5.1)
$dir = $PSScriptRoot
$job = Start-Job -ArgumentList (Join-Path $dir "www") -FilePath (Join-Path $dir "srv.ps1")
Start-Sleep 2
function Run([string]$case, [string]$script = "install-test.ps1", [string]$extra = "") {
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$dir\$script' -Server http://127.0.0.1:8480/$case -Code CODE123 $extra" 2>&1 | Out-String
    $last = ($out.Trim() -split "`r?`n" | Where-Object { $_ -match "cybercop-agent:" } | Select-Object -Last 1)
    "  [{0}{1}] rc={2} :: {3}" -f $case, $(if ($script -ne "install-test.ps1") { " $script" } else { "" }), $LASTEXITCODE, ($last -replace '^.*?(cybercop-agent:)', '$1')
    $out
}
function Clean { & powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$dir\install-test.ps1' -Uninstall" | Out-Null }
Clean
"== expected: good installs (spare key); every other case refuses"
foreach ($c in "foreign", "unsigned", "old", "tampered", "swapped", "linuxsig") { (Run $c)[0]; if (Get-Service CybercopAgent -ErrorAction SilentlyContinue) { "     FAIL: service exists after refusal" } }
(Run "good" "install-nokeys.ps1")[0]
$r = Run "good"; $r[0]; ($r[1] -split "`r?`n" | Where-Object { $_ -match "signature checked" }) -replace '^', '     '
$svc = Get-CimInstance Win32_Service -Filter "Name='CybercopAgent'"
"     service: state={0} account={1} start={2}" -f $svc.State, $svc.StartName, $svc.StartMode
$t = Get-ScheduledTask -TaskName CybercopAgent
"     task: principal={0} state={1} triggers={2}" -f $t.Principal.UserId, $t.State, $t.Triggers.Count
"     state ACL: " + ((Get-Acl C:\ProgramData\CybercopAgent).Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
"     out ACL:   " + ((Get-Acl C:\ProgramData\CybercopAgent\out).Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
"     enrolled: " + (Test-Path C:\ProgramData\CybercopAgent\agent.json) + ", key: " + (Test-Path C:\ProgramData\CybercopAgent\key)
$i = 0; while (-not (Test-Path C:\ProgramData\CybercopAgent\out\inventory.json) -and $i -lt 90) { Start-Sleep 2; $i++ }
foreach ($f in "indicators.json", "inventory.json") { $p = "C:\ProgramData\CybercopAgent\out\$f"; "     out\{0}: {1}" -f $f, $(if (Test-Path $p) { "$((Get-Item $p).Length) bytes" } else { "MISSING" }) }
Start-Sleep 5
"     system.log: " + ((Get-Content C:\ProgramData\CybercopAgent\log\system.log -ErrorAction SilentlyContinue | Select-Object -Last 2) -join " | ")
"     service.log: " + ((Get-Content C:\ProgramData\CybercopAgent\log\service.log -ErrorAction SilentlyContinue | Select-Object -Last 3) -join " | ")
$pid1 = $svc.ProcessId
"== reinstall over a running agent (expected: new process)"
(Run "good")[0]
$pid2 = (Get-CimInstance Win32_Service -Filter "Name='CybercopAgent'").ProcessId
"     service PID $pid1 -> $pid2" + $(if ($pid1 -ne $pid2 -and $pid2 -ne 0) { "" } else { "  FAIL" })
function Hb([string]$json, [string]$status = "") {
    $d = Join-Path $dir "www\good\agent-api\v1"
    if ($json) { Copy-Item $json (Join-Path $d "heartbeat.json") -Force } else { Remove-Item (Join-Path $d "heartbeat.json") -ErrorAction SilentlyContinue }
    if ($status) { Set-Content (Join-Path $d "heartbeat.status") $status } else { Remove-Item (Join-Path $d "heartbeat.status") -ErrorAction SilentlyContinue }
}
function Tick { Start-ScheduledTask -TaskName CybercopAgent; Start-Sleep 3; $i = 0; while ((Get-ScheduledTask -TaskName CybercopAgent).State -eq "Running" -and $i -lt 120) { Start-Sleep 1; $i++ } }
$bin = "C:\Program Files\CybercopAgent\cybercop-agent.exe"
$state = "C:\ProgramData\CybercopAgent"
"== self-update offered with a foreign signature (expected: refused by the service, binary unchanged)"
$h0 = (Get-FileHash $bin).Hash
Hb (Join-Path $dir "offer-foreign.json"); Restart-Service CybercopAgent; Start-Sleep 8
"     ready file: " + (Test-Path "$state\update\ready") + ", binary unchanged: " + ((Get-FileHash $bin).Hash -eq $h0)
"     service.log: " + ((Get-Content "$state\log\service.log" | Select-String "update" | Select-Object -Last 1) -replace '^\S+ \S+ ', '')
"== self-update offered with a valid signature (expected: service downloads, SYSTEM task installs, service restarts)"
Hb (Join-Path $dir "offer-good.json"); $p0 = (Get-CimInstance Win32_Service -Filter "Name='CybercopAgent'").ProcessId
Restart-Service CybercopAgent; Start-Sleep 8
"     ready file after heartbeat: " + (Test-Path "$state\update\ready")
Hb ""; $p1 = (Get-CimInstance Win32_Service -Filter "Name='CybercopAgent'").ProcessId; Tick; Start-Sleep 3
$p2 = (Get-CimInstance Win32_Service -Filter "Name='CybercopAgent'").ProcessId
$want = (Get-Content (Join-Path $dir "new.sha256")).Trim()
"     binary is the signed 9.9.9 file: " + ((Get-FileHash $bin).Hash.ToLower() -eq $want) + ", service PID $p1 -> $p2, state " + (Get-Service CybercopAgent).Status
"     system.log: " + ((Get-Content "$state\log\system.log" | Select-String "updated|refused" | Select-Object -Last 1) -replace '^\S+ \S+ ', '')
"     update folder empty: " + (-not (Get-ChildItem "$state\update" -ErrorAction SilentlyContinue))
"== revoked in the control centre (expected: service stops working, SYSTEM task does nothing)"
Set-Content (Join-Path $dir "www\good\agent-api\v1\heartbeat.json") '{"error": "revoked"}'; Set-Content (Join-Path $dir "www\good\agent-api\v1\heartbeat.status") "401"
Restart-Service CybercopAgent; Start-Sleep 8
"     revoked mark: " + (Test-Path "$state\revoked") + ", service: " + (Get-Service CybercopAgent).Status
"     service.log: " + ((Get-Content "$state\log\service.log" | Select-Object -Last 2) -replace '^\S+ \S+ ', '') -join " | "
Remove-Item "$state\out\indicators.json" -ErrorAction SilentlyContinue; Tick
"     SYSTEM task after revocation wrote nothing: " + (-not (Test-Path "$state\out\indicators.json"))
Hb ""
"== uninstall"
Clean
"     service: " + [bool](Get-Service CybercopAgent -ErrorAction SilentlyContinue) + ", task: " + [bool](Get-ScheduledTask -TaskName CybercopAgent -ErrorAction SilentlyContinue) + ", files: " + (Test-Path "C:\Program Files\CybercopAgent") + "/" + (Test-Path C:\ProgramData\CybercopAgent)
try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8480/stop | Out-Null } catch {}
Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
