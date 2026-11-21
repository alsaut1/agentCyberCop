# Checks the Ed25519 verification written out in dist/install.ps1 against the RFC 8032 test vectors (section 7.1),
# plus signatures that must be refused. Runs the exact code from the installer (between the BEGIN/END ed25519 marks).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\test-install\ed25519-vectors.ps1 [path\to\install.ps1]
param([string]$Installer = (Join-Path $PSScriptRoot "..\..\dist\install.ps1"))
$ErrorActionPreference = "Stop"
$text = Get-Content -Raw -Path $Installer
$m = [regex]::Match($text, '(?s)# BEGIN ed25519.*?# END ed25519')
if (-not $m.Success) { throw "no ed25519 block in $Installer" }
. ([scriptblock]::Create($m.Value))

function Hex([string]$h) { if (-not $h) { return , [byte[]]@() }; , [byte[]]($h -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }) }
$fail = 0
function Check([string]$name, [bool]$expected, [byte[]]$pub, [byte[]]$msg, [byte[]]$sig) {
    $t = [Diagnostics.Stopwatch]::StartNew()
    $got = Test-Ed25519 $pub $msg $sig
    $ok = ($got -eq $expected)
    if (-not $ok) { $script:fail++ }
    "{0,-4} {1,-58} expected={2,-5} got={3,-5} {4} ms" -f $(if ($ok) { "ok" } else { "FAIL" }), $name, $expected, $got, $t.ElapsedMilliseconds
}

# RFC 8032, 7.1: TEST 1, TEST 2, TEST 3, TEST SHA(abc)
$v = @(
    @("TEST 1 (empty message)", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    @("TEST 2 (1 byte)", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    @("TEST 3 (2 bytes)", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    @("TEST SHA(abc) (64 bytes)", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")
)
foreach ($t in $v) { Check $t[0] $true (Hex $t[1]) (Hex $t[2]) (Hex $t[3]) }

# Must be refused.
$pub = Hex $v[1][1]; $msg = Hex $v[1][2]; $sig = Hex $v[1][3]
$s = [byte[]]$sig.Clone(); $s[0] = $s[0] -bxor 1; Check "TEST 2, one bit of R changed" $false $pub $msg $s
$s = [byte[]]$sig.Clone(); $s[40] = $s[40] -bxor 1; Check "TEST 2, one bit of S changed" $false $pub $msg $s
Check "TEST 2, other message" $false $pub (Hex "73") $sig
Check "TEST 2, signature checked with TEST 3 key" $false (Hex $v[2][1]) $msg $sig
Check "TEST 2, empty message instead of 1 byte" $false $pub (Hex "") $sig
# S + L: the same point, a malleable copy of a valid signature; must be refused (S < L).
$S = EdInt ([byte[]]$sig[32..63]); $SL = ($S + $script:EdL).ToByteArray(); $sl = New-Object byte[] 32; [Array]::Copy($SL, $sl, [Math]::Min(32, $SL.Length))
Check "TEST 2, S replaced by S + L" $false $pub $msg ([byte[]]($sig[0..31] + $sl))
Check "TEST 2, signature 63 bytes" $false $pub $msg ([byte[]]$sig[0..62])
Check "TEST 2, all-zero signature" $false $pub $msg (New-Object byte[] 64)
Check "public key not a point (y = 2)" $false (Hex "0200000000000000000000000000000000000000000000000000000000000000") $msg $sig
Check "public key 31 bytes" $false ([byte[]]$pub[0..30]) $msg $sig

if ($fail -gt 0) { Write-Host "$fail check(s) failed"; exit 1 }
Write-Host "all checks passed"
