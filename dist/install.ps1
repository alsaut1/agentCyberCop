# HT CYBERCOP agent (Watcher) installer for Windows Server 2016, 2019, 2022 and 2025.
#
# Run in PowerShell as Administrator:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/alsaut1/agentCyberCop/vX.Y.Z/dist/install.ps1))) -Code CODE
#
# CODE is the one-time code from the control centre. Take this script from the public repository, not from the
# control centre: the release keys below are what makes the download trustworthy. The script asks the control centre
# which version is current, downloads it, and installs it only if its Ed25519 signature verifies with one of the
# release keys (main or spare) and the version is not older than this script. The signature is made offline by the
# maintainer; the control centre cannot produce one. Windows has no built-in Ed25519, so the check is written out
# below (RFC 8032) and tested against the RFC test vectors (tools/test-install/ed25519-vectors.ps1).
#
# What it installs: C:\Program Files\CybercopAgent\cybercop-agent.exe; the service CybercopAgent under its own
# unprivileged account (NT SERVICE\CybercopAgent), which sends the data; the scheduled task CybercopAgent, which runs
# every 5 minutes as SYSTEM, collects what needs privileges (Windows Update, owners of listening ports, all scheduled
# tasks) and installs checked updates; the state folder C:\ProgramData\CybercopAgent. The agent only reads and
# reports; it opens no ports.
#
#   -Server URL     another control centre (https only)
#   -Uninstall      remove the agent
param(
    [string]$Code = "",
    [string]$Server = "https://agent.cybercop.gtva.net",
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

# Oldest version this installer accepts: the version of the tag it was published with.
$MinVersion = "0.2.0"
# Release keys, "name:base64-public-key": main and spare (the maintainer keeps the secret halves offline).
$ReleaseKeys = @("main:v1uiLKxvYbHr42+wVOqPtFOWNk/IxiElaVT1uGvRg+k=", "spare:ilfuIb2sW3tq5YJQDx9fLwRicTvrA+8j8VO498GVIuQ=")
$Prefix = "cybercop-agent-release-v1"
$Arch = "windows-x86_64"
$ServiceName = "CybercopAgent"
$ServiceAccount = "NT SERVICE\CybercopAgent"
$BinDir = Join-Path $env:ProgramFiles "CybercopAgent"
$Bin = Join-Path $BinDir "cybercop-agent.exe"
$State = Join-Path $env:ProgramData "CybercopAgent"

function Say([string]$m) { Write-Host "cybercop-agent: $m" }
# Stop with an error. Not `exit`: the script runs inside the administrator's own PowerShell window, which `exit`
# would close.
function Die([string]$m) { throw "cybercop-agent: $m" }

# BEGIN ed25519 (RFC 8032 verification; extracted and tested by tools/test-install/ed25519-vectors.ps1)
Add-Type -AssemblyName System.Numerics
$script:EdP = [System.Numerics.BigInteger]::Pow(2, 255) - 19
$script:EdL = [System.Numerics.BigInteger]::Pow(2, 252) + [System.Numerics.BigInteger]::Parse("27742317777372353535851937790883648493")
function EdMod([System.Numerics.BigInteger]$a) { $r = [System.Numerics.BigInteger]::Remainder($a, $script:EdP); if ($r.Sign -lt 0) { $r += $script:EdP }; $r }
function EdInv([System.Numerics.BigInteger]$a) { [System.Numerics.BigInteger]::ModPow($a, $script:EdP - 2, $script:EdP) }
$script:EdD = EdMod ((-121665) * (EdInv 121666))
$script:EdD2 = EdMod (2 * $script:EdD)
$script:EdI = [System.Numerics.BigInteger]::ModPow(2, ($script:EdP - 1) / 4, $script:EdP)
function EdInt([byte[]]$b) { [System.Numerics.BigInteger]::new([byte[]]($b + [byte[]]@(0))) }
# Points in extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z.
function EdAdd($P, $Q) {
    $A = EdMod (($P[1] - $P[0]) * ($Q[1] - $Q[0]))
    $B = EdMod (($P[1] + $P[0]) * ($Q[1] + $Q[0]))
    $C = EdMod ($P[3] * $script:EdD2 * $Q[3])
    $D = EdMod (2 * $P[2] * $Q[2])
    $E = $B - $A; $F = $D - $C; $G = $D + $C; $H = $B + $A
    , @((EdMod ($E * $F)), (EdMod ($G * $H)), (EdMod ($F * $G)), (EdMod ($E * $H)))
}
function EdMul([System.Numerics.BigInteger]$s, $P) {
    $R = @([System.Numerics.BigInteger]::Zero, [System.Numerics.BigInteger]::One, [System.Numerics.BigInteger]::One, [System.Numerics.BigInteger]::Zero)
    while ($s.Sign -gt 0) {
        if (-not $s.IsEven) { $R = EdAdd $R $P }
        $P = EdAdd $P $P
        $s = $s / 2
    }
    , $R
}
# 32 bytes -> point, or $null if the encoding is not a valid point.
function EdDecode([byte[]]$b) {
    if ($b.Length -ne 32) { return $null }
    $c = [byte[]]$b.Clone()
    $sign = ($c[31] -shr 7) -band 1
    $c[31] = $c[31] -band 0x7f
    $y = EdInt $c
    if ($y -ge $script:EdP) { return $null }
    $u = EdMod ($y * $y - 1)
    $v = EdMod ($script:EdD * $y * $y + 1)
    $v3 = EdMod ($v * $v * $v)
    $x = EdMod ($u * $v3 * [System.Numerics.BigInteger]::ModPow((EdMod ($u * $v3 * $v3 * $v)), ($script:EdP - 5) / 8, $script:EdP))
    $vx2 = EdMod ($v * $x * $x)
    if ($vx2 -ne $u) {
        if ($vx2 -eq (EdMod (-$u))) { $x = EdMod ($x * $script:EdI) } else { return $null }
    }
    if ($x.IsZero -and $sign -eq 1) { return $null }
    if ([int]($x % 2) -ne $sign) { $x = $script:EdP - $x }
    , @($x, $y, [System.Numerics.BigInteger]::One, (EdMod ($x * $y)))
}
function EdEncode($P) {
    $zi = EdInv $P[2]
    $x = EdMod ($P[0] * $zi); $y = EdMod ($P[1] * $zi)
    $raw = $y.ToByteArray()
    $out = New-Object byte[] 32
    [Array]::Copy($raw, $out, [Math]::Min(32, $raw.Length))
    if (-not $x.IsEven) { $out[31] = $out[31] -bor 0x80 }
    , $out
}
$script:EdB = EdDecode ([byte[]](0x58) + [byte[]](@(0x66) * 31))
# True only if $Sig (64 bytes) is a valid signature of $Msg under the public key $Pub (32 bytes).
function Test-Ed25519([byte[]]$Pub, [byte[]]$Msg, [byte[]]$Sig) {
    if ($null -eq $Pub -or $null -eq $Sig -or $Pub.Length -ne 32 -or $Sig.Length -ne 64) { return $false }
    $A = EdDecode $Pub
    if ($null -eq $A) { return $false }
    $Rb = [byte[]]$Sig[0..31]
    $S = EdInt ([byte[]]$Sig[32..63])
    if ($S -ge $script:EdL) { return $false }
    $buf = New-Object System.IO.MemoryStream
    $buf.Write($Rb, 0, 32); $buf.Write($Pub, 0, 32)
    if ($null -ne $Msg -and $Msg.Length -gt 0) { $buf.Write($Msg, 0, $Msg.Length) }
    $h = [System.Security.Cryptography.SHA512]::Create().ComputeHash($buf.ToArray())
    $k = [System.Numerics.BigInteger]::Remainder((EdInt $h), $script:EdL)
    # [S]B - [k]A must encode exactly to R.
    $kA = EdMul $k $A
    $negkA = @((EdMod (-$kA[0])), $kA[1], $kA[2], (EdMod (-$kA[3])))
    $check = EdEncode (EdAdd (EdMul $S $script:EdB) $negkA)
    for ($i = 0; $i -lt 32; $i++) { if ($check[$i] -ne $Rb[$i]) { return $false } }
    $true
}
# END ed25519

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-Agent {
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    Remove-Item -Recurse -Force $BinDir, $State -ErrorAction SilentlyContinue
}

function Compare-Version([string]$a, [string]$b) {
    $x = $a.Split("."); $y = $b.Split(".")
    for ($i = 0; $i -lt 3; $i++) {
        $d = [int]$x[$i] - [int]$y[$i]
        if ($d -ne 0) { return $d }
    }
    0
}

if (-not (Test-Admin)) { Die "run PowerShell as Administrator" }
if ($Uninstall) {
    Remove-Agent
    Say "removed. Revoke the agent in the control centre as well."
    return
}
if (-not $Code) { Die "usage: & ([scriptblock]::Create((irm <installer URL>))) -Code CODE   (the one-time code from the control centre)" }
if (-not $Server.StartsWith("https://")) { Die "the control centre address must start with https://" }
if (-not $ReleaseKeys) { Die "this installer has no release keys, so nothing can be verified; not installing" }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) { Die "Windows 10 and 11 are not supported; the agent is for Windows Server 2016-2025" }
if ([int]$os.BuildNumber -lt 14393) { Die "Windows Server 2016 or newer is required" }
if (-not [Environment]::Is64BitOperatingSystem) { Die "a 64-bit Windows is required" }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# The download goes straight into the agent's folder (not %TEMP%): that folder is what the administrator adds to the
# antivirus exclusions, so the file is not deleted half-way.
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$file = Join-Path $BinDir "cybercop-agent.download"
try {
    try {
        $rel = Invoke-RestMethod -UseBasicParsing -Uri "$Server/agent-api/v1/release?arch=$Arch"
    } catch {
        Die "the control centre has no signed version for Windows yet, or cannot be reached: $($_.Exception.Message)"
    }
    $version = [string]$rel.version; $sha = ([string]$rel.sha256).ToLower(); $sig = [string]$rel.signature
    if ($version -notmatch '^\d+\.\d+\.\d+$' -or $sha -notmatch '^[0-9a-f]{64}$' -or -not $sig) { Die "the control centre gave an unusable answer; not installing" }
    if ((Compare-Version $version $MinVersion) -lt 0) { Die "the control centre offers $version, older than this installer ($MinVersion); not installing" }
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent-api/v1/download/$version/$Arch" -OutFile $file
    $got = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower()
    if ($got -ne $sha) { Die "checksum mismatch, not installing" }
    try { $sigBytes = [Convert]::FromBase64String($sig) } catch { Die "the signature of $version is not valid; not installing" }
    $msg = [Text.Encoding]::ASCII.GetBytes("$Prefix`n$version`n$Arch`n$sha")
    $signedBy = $null
    foreach ($entry in $ReleaseKeys) {
        $name, $key = $entry.Split(":", 2)
        if (Test-Ed25519 ([Convert]::FromBase64String($key)) $msg $sigBytes) { $signedBy = $name; break }
    }
    if (-not $signedBy) { Die "the signature of $version does not match the release keys; not installing" }
    Say "version $version, signature checked ($signedBy key)"

    # Install or reinstall: a running agent is stopped first and started again on the new file.
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
        Disable-ScheduledTask -TaskName $ServiceName | Out-Null
        Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Stop-Service -Name $ServiceName -Force }
    Move-Item -Force -Path $file -Destination $Bin
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        # New-Service keeps the quotes around the path (sc.exe create loses them under PowerShell 5.1).
        New-Service -Name $ServiceName -BinaryPathName "`"$Bin`" run" -DisplayName "HT CYBERCOP agent" -StartupType Automatic | Out-Null
        & sc.exe config $ServiceName obj= $ServiceAccount start= delayed-auto | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "could not set the service account" }
        & sc.exe description $ServiceName "HT CYBERCOP agent (Watcher): read-only inventory and signs of a break-in" | Out-Null
        & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
    }
    # State folder: SYSTEM and Administrators full, the service account can change (key, settings, downloads);
    # out\ (written by the SYSTEM task) is read-only for the service account. Nobody else has access.
    New-Item -ItemType Directory -Force -Path $State, (Join-Path $State "out"), (Join-Path $State "log") | Out-Null
    & icacls.exe $State /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccount}:(OI)(CI)M" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "could not set access to $State" }
    & icacls.exe (Join-Path $State "out") /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "${ServiceAccount}:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "could not set access to $State\out" }
    # Files already there (a reinstall) take the folder's access list.
    Get-ChildItem -Path $State -Recurse -File | ForEach-Object { & icacls.exe $_.FullName /reset /Q | Out-Null }
    if (-not (Test-Path (Join-Path $State "agent.json"))) {
        & $Bin enroll --server $Server $Code
        if ($LASTEXITCODE -ne 0) { Die "registration failed" }
    }
    # SYSTEM part: every 5 minutes and at start-up, one instance at a time.
    $action = New-ScheduledTaskAction -Execute $Bin -Argument "system-tick"
    $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
    $boot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger @($every, $boot) -Principal $principal -Settings $settings -Description "HT CYBERCOP agent: collect what needs privileges, install checked updates" -Force | Out-Null
    Start-Service -Name $ServiceName
    Start-ScheduledTask -TaskName $ServiceName
    Say "installed $version; the first inventory appears in the control centre within a few minutes"
} finally {
    Remove-Item -Force $file -ErrorAction SilentlyContinue
}
