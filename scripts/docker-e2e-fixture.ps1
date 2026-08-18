[CmdletBinding()]
param(
    [int]$Port = 56999
)

$ErrorActionPreference = "Stop"

function Get-SHA256Digest([byte[]]$Bytes) {
    $hash = [System.Security.Cryptography.SHA256]::HashData($Bytes)
    return "sha256:" + [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Write-HTTPResponse([System.Net.Sockets.NetworkStream]$Stream, [int]$Status, [string]$Reason, [hashtable]$Headers, [byte[]]$Body, [bool]$WriteBody) {
    $encoding = [System.Text.Encoding]::ASCII
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("HTTP/1.1 $Status $Reason")
    foreach ($name in $Headers.Keys) {
        $lines.Add("${name}: $($Headers[$name])")
    }
    $lines.Add("")
    $lines.Add("")
    $headerBytes = $encoding.GetBytes(($lines -join "`r`n"))
    $Stream.Write($headerBytes, 0, $headerBytes.Length)
    if ($WriteBody -and $null -ne $Body -and $Body.Length -gt 0) {
        $Stream.Write($Body, 0, $Body.Length)
    }
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
$configBytes = $utf8.GetBytes('{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]},"history":[{"created_by":"drg fixture"}]}')
$configDigest = Get-SHA256Digest $configBytes
$manifestText = '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"' + $configDigest + '","size":' + $configBytes.Length + '},"layers":[]}'
$manifestBytes = $utf8.GetBytes($manifestText)
$manifestDigest = Get-SHA256Digest $manifestBytes
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
$listener.Start()

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII, $false, 4096, $true)
            $requestLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($requestLine)) {
                continue
            }
            $headers = @{}
            while ($true) {
                $line = $reader.ReadLine()
                if ($null -eq $line -or $line.Length -eq 0) {
                    break
                }
                $separator = $line.IndexOf(':')
                if ($separator -gt 0) {
                    $headers[$line.Substring(0, $separator)] = $line.Substring($separator + 1).Trim()
                }
            }
            $parts = $requestLine.Split(' ')
            $method = $parts[0]
            $path = $parts[1].Split('?')[0]
            $responseHeaders = @{ "Docker-Distribution-API-Version" = "registry/2.0"; "Connection" = "close" }
            $body = [byte[]]@()
            $status = 200
            $reason = "OK"

            if ($path -eq "/v2/" -or $path -eq "/v2") {
                $null = $responseHeaders
            } elseif ($path -eq "/v2/library/empty/manifests/latest" -or $path -eq "/v2/library/empty/manifests/$manifestDigest") {
                $body = $manifestBytes
                $responseHeaders["Content-Type"] = "application/vnd.oci.image.manifest.v1+json"
                $responseHeaders["Docker-Content-Digest"] = $manifestDigest
            } elseif ($path -eq "/v2/library/empty/blobs/$configDigest") {
                $body = $configBytes
                $responseHeaders["Content-Type"] = "application/vnd.oci.image.config.v1+json"
                $responseHeaders["Docker-Content-Digest"] = $configDigest
                if ($headers.ContainsKey("Range") -and $headers["Range"] -match '^bytes=(\d+)-(\d*)$') {
                    $start = [int]$Matches[1]
                    $end = if ($Matches[2] -eq "") { $configBytes.Length - 1 } else { [int]$Matches[2] }
                    if ($start -ge $configBytes.Length -or $end -lt $start) {
                        Write-HTTPResponse $stream 416 "Range Not Satisfiable" @{ "Content-Length" = "0"; "Connection" = "close" } ([byte[]]@()) $false
                        continue
                    }
                    if ($end -ge $configBytes.Length) { $end = $configBytes.Length - 1 }
                    $length = $end - $start + 1
                    $rangeBody = [byte[]]::new($length)
                    [Array]::Copy($configBytes, $start, $rangeBody, 0, $length)
                    $body = $rangeBody
                    $status = 206
                    $reason = "Partial Content"
                    $responseHeaders["Content-Range"] = "bytes $start-$end/$($configBytes.Length)"
                }
            } else {
                $status = 404
                $reason = "Not Found"
                $body = [byte[]]@()
            }
            $responseHeaders["Content-Length"] = [string]$body.Length
            Write-HTTPResponse $stream $status $reason $responseHeaders $body ($method -ne "HEAD")
        } finally {
            $client.Close()
        }
    }
} finally {
    $listener.Stop()
}
