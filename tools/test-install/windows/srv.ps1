# Local HTTP server for cases.ps1: serves the fake releases from www\, answers enrolment. Test machine only.
param([string]$Root, [int]$Port = 8480)
$l = New-Object Net.HttpListener
$l.Prefixes.Add("http://127.0.0.1:$Port/")
$l.Start()
while ($l.IsListening) {
    $c = $l.GetContext()
    $path = $c.Request.Url.AbsolutePath
    $code = 200; $body = $null
    if ($c.Request.HttpMethod -eq "POST" -and $path -like "*/agent-api/v1/enroll") {
        $body = [Text.Encoding]::UTF8.GetBytes('{"agent_id": "stand", "intervals": {"heartbeat": 300, "indicators": 900, "inventory": 21600}}')
    } elseif ($c.Request.HttpMethod -eq "POST" -and $path -like "*/agent-api/v1/heartbeat") {
        # cases.ps1 puts an answer next to the release: heartbeat.json (e.g. an update offer), heartbeat.status.
        $d = Join-Path $Root ((Split-Path $path).TrimStart("\/").Replace("/", "\"))
        $hb = Join-Path $d "heartbeat.json"; $st = Join-Path $d "heartbeat.status"
        $body = if (Test-Path $hb) { [IO.File]::ReadAllBytes($hb) } else { [Text.Encoding]::UTF8.GetBytes('{}') }
        if (Test-Path $st) { $code = [int](Get-Content $st) }
    } elseif ($c.Request.HttpMethod -eq "POST") {
        $body = [Text.Encoding]::UTF8.GetBytes('{}')
    } elseif ($path -eq "/stop") {
        $body = [byte[]]@(); $l.Stop()
    } else {
        $f = Join-Path $Root ($path.TrimStart("/").Replace("/", "\"))
        if (Test-Path -PathType Leaf $f) { $body = [IO.File]::ReadAllBytes($f) } else { $code = 404; $body = [Text.Encoding]::UTF8.GetBytes('{"error": "unsigned"}') }
    }
    if ($l.IsListening -or $path -eq "/stop") {
        $c.Response.StatusCode = $code
        $c.Response.OutputStream.Write($body, 0, $body.Length)
        $c.Response.Close()
    }
}
