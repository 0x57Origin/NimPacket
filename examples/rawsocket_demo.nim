## Raw Socket Demo - Practical examples of sending and receiving packets
##
## **IMPORTANT:** This demo must be run with Administrator privileges on Windows
## or as root on Unix-like systems.
##
## This demo shows:
## 1. Privilege checking
## 2. ICMP Echo Request (ping) to a public DNS server
## 3. TCP SYN packet to test port connectivity
## 4. Receiving and parsing responses
##
## **SAFETY:** This demo only contacts safe, public DNS servers (1.1.1.1, 8.8.8.8)
## and includes proper rate limiting and cleanup.

import ../src/[nimpacket, rawsocket]
import std/[strformat, strutils, times, os, random]

# Configuration
const
  SAFE_TARGET_DNS = "8.8.8.8"  # Google Public DNS
  SAFE_TARGET_CLOUDFLARE = "1.1.1.1"  # Cloudflare DNS
  LOCAL_SOURCE_IP = "0.0.0.0"  # Will be filled by OS if set to 0.0.0.0

proc separator(title: string = "") =
  echo ""
  if title.len > 0:
    echo repeat("=", 60)
    echo title
    echo repeat("=", 60)
  else:
    echo repeat("-", 60)

proc sleepMs(ms: int) =
  ## Rate limiting helper
  sleep(ms)

proc demo1_CheckPrivileges() =
  ## Demo 1: Check if we have the required privileges
  separator("Demo 1: Privilege Check")

  echo "Checking for Administrator/root privileges..."

  if isRunningAsAdmin():
    echo "✓ Running with sufficient privileges!"
    echo "  You can create raw sockets."
  else:
    echo "✗ Insufficient privileges!"
    echo ""
    echo "To run this demo, you need:"
    when defined(windows):
      echo "  - Windows: Run as Administrator"
      echo "    (Right-click -> Run as Administrator)"
    else:
      echo "  - Linux/Unix: Run as root (sudo)"
      echo "    Example: sudo ./rawsocket_demo"
    echo ""
    quit(1)

proc demo2_ICMPPing() =
  ## Demo 2: Send an ICMP Echo Request (ping) and receive the reply
  separator("Demo 2: ICMP Ping")

  echo fmt"Sending ICMP Echo Request to {SAFE_TARGET_DNS}..."

  try:
    # Create ICMP raw socket
    let sock = createICMPSocket()
    defer:
      var s = sock
      s.close()

    # Build IPv4 header
    let srcIP = parseIPv4("192.168.1.10")  # Source IP (can be spoofed for ICMP)
    let dstIP = parseIPv4(SAFE_TARGET_DNS)

    # Build ICMP Echo Request
    var icmp = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0,
      identifier: 1234,
      sequenceNumber: 1
    )

    # Payload data
    let payload = "NimPacket ICMP Ping Test".toBytes()

    # Calculate ICMP checksum
    icmp.checksum = calculateICMPChecksum(icmp, payload)

    # Build IP header
    var ip = IPv4Header(
      version: 4,
      headerLength: 5,  # 5 * 4 = 20 bytes (no options)
      typeOfService: 0,
      totalLength: (20 + 8 + payload.len).uint16,  # IP + ICMP + payload
      identification: rand(65535).uint16,
      flags: 0,
      timeToLive: 64,
      protocol: IPPROTO_ICMP,
      checksum: 0,
      sourceIP: srcIP,
      destIP: dstIP
    )

    # Calculate IP checksum
    ip.checksum = calculateIPv4Checksum(ip)

    # Build complete packet
    let packet = (ip / icmp / payload).toBytes()

    echo fmt"  Packet size: {packet.len} bytes"
    echo fmt"  ICMP ID: {icmp.identifier}, Sequence: {icmp.sequenceNumber}"
    echo fmt"  Payload: {payload.len} bytes"

    # Send the packet
    let startTime = epochTime()
    let bytesSent = sock.sendPacket(packet, SAFE_TARGET_DNS)
    echo fmt"  Sent {bytesSent} bytes"

    # Wait for response
    echo "  Waiting for reply..."
    let response = sock.receivePacketWithTimeout(5.0) do (data: seq[byte]) -> bool:
      # Filter for ICMP Echo Reply from our target
      if data.len < 20:
        return false

      try:
        let pkt = parsePacket(data)
        return pkt.ipv4.protocol == IPPROTO_ICMP and
               pkt.icmp.icmpType == ICMP_ECHO_REPLY and
               pkt.icmp.identifier == icmp.identifier and
               ipToString(pkt.ipv4.sourceIP) == SAFE_TARGET_DNS
      except:
        return false

    if response.len > 0:
      let rtt = (epochTime() - startTime) * 1000  # Round-trip time in ms
      let parsed = parsePacket(response)

      echo "  ✓ Received ICMP Echo Reply!"
      echo fmt"    From: {ipToString(parsed.ipv4.sourceIP)}"
      echo fmt"    TTL: {parsed.ipv4.timeToLive}"
      echo fmt"    Round-trip time: {rtt:.2f} ms"
      echo fmt"    Payload size: {parsed.payload.len} bytes"
    else:
      echo "  ✗ Timeout - no reply received"
      echo "    (This is normal if ICMP is filtered)"

  except PrivilegeError as e:
    echo "  ✗ Error: ", e.msg
  except Exception as e:
    echo "  ✗ Error: ", e.msg
    echo "    ", e.getStackTrace()

proc demo3_TCPSyn() =
  ## Demo 3: Send a TCP SYN packet to test port connectivity
  separator("Demo 3: TCP SYN Scan")

  echo fmt"Sending TCP SYN to {SAFE_TARGET_CLOUDFLARE}:443 (HTTPS)..."

  try:
    # Create TCP raw socket
    let sock = createTCPSocket()
    defer:
      var s = sock
      s.close()

    # Build IPv4 header
    let srcIP = parseIPv4("192.168.1.10")  # Source IP
    let dstIP = parseIPv4(SAFE_TARGET_CLOUDFLARE)

    # Build TCP header with SYN flag
    let srcPort = (30000 + rand(20000)).uint16  # Random high port
    let dstPort = 443.uint16  # HTTPS port

    var tcp = TCPHeader(
      sourcePort: srcPort,
      destPort: dstPort,
      sequenceNumber: rand(int.high).uint32,
      acknowledgmentNumber: 0,
      headerLength: 5,  # 5 * 4 = 20 bytes (no options)
      flags: TCP_SYN,
      windowSize: 65535,
      checksum: 0,
      urgentPointer: 0
    )

    # Build IP header
    var ip = IPv4Header(
      version: 4,
      headerLength: 5,
      typeOfService: 0,
      totalLength: 40,  # 20 IP + 20 TCP
      identification: rand(65535).uint16,
      flags: 0x4000,  # Don't fragment
      timeToLive: 64,
      protocol: IPPROTO_TCP,
      checksum: 0,
      sourceIP: srcIP,
      destIP: dstIP
    )

    # Calculate TCP checksum
    tcp.checksum = calculateTCPChecksum(ip, tcp, @[])

    # Calculate IP checksum
    ip.checksum = calculateIPv4Checksum(ip)

    # Build complete packet
    let packet = (ip / tcp).toBytes()

    echo fmt"  Source: 192.168.1.10:{srcPort}"
    echo fmt"  Destination: {SAFE_TARGET_CLOUDFLARE}:{dstPort}"
    echo fmt"  TCP Flags: SYN"
    echo fmt"  Sequence Number: {tcp.sequenceNumber}"
    echo fmt"  Packet size: {packet.len} bytes"

    # Send the packet
    let startTime = epochTime()
    let bytesSent = sock.sendPacket(packet, SAFE_TARGET_CLOUDFLARE)
    echo fmt"  Sent {bytesSent} bytes"

    # Wait for response (SYN-ACK or RST)
    echo "  Waiting for response..."
    let response = sock.receivePacketWithTimeout(5.0) do (data: seq[byte]) -> bool:
      # Filter for TCP response from our target to our source port
      if data.len < 40:  # Minimum IP + TCP
        return false

      try:
        let pkt = parsePacket(data)
        return pkt.ipv4.protocol == IPPROTO_TCP and
               pkt.tcp.destPort == srcPort and
               pkt.tcp.sourcePort == dstPort and
               ipToString(pkt.ipv4.sourceIP) == SAFE_TARGET_CLOUDFLARE
      except:
        return false

    if response.len > 0:
      let rtt = (epochTime() - startTime) * 1000
      let parsed = parsePacket(response)

      echo "  ✓ Received TCP Response!"
      echo fmt"    From: {ipToString(parsed.ipv4.sourceIP)}:{parsed.tcp.sourcePort}"
      echo fmt"    To: {ipToString(parsed.ipv4.destIP)}:{parsed.tcp.destPort}"
      echo fmt"    Round-trip time: {rtt:.2f} ms"

      # Check flags
      if (parsed.tcp.flags and TCP_SYN) != 0 and (parsed.tcp.flags and TCP_ACK) != 0:
        echo "    Flags: SYN+ACK (port is OPEN)"
        echo fmt"    Acknowledgment: {parsed.tcp.acknowledgmentNumber}"
      elif (parsed.tcp.flags and TCP_RST) != 0:
        echo "    Flags: RST (port is CLOSED or filtered)"
      else:
        echo fmt"    Flags: 0x{parsed.tcp.flags:04x}"

    else:
      echo "  ✗ Timeout - no response received"
      echo "    (Port may be filtered or host is down)"

  except PrivilegeError as e:
    echo "  ✗ Error: ", e.msg
  except Exception as e:
    echo "  ✗ Error: ", e.msg
    echo "    ", e.getStackTrace()

proc demo4_BuildingPackets() =
  ## Demo 4: Building different types of packets
  separator("Demo 4: Building Packets (No Send)")

  echo "Building various packet types without sending..."
  echo ""

  # TCP packet
  echo "1. TCP SYN packet to 192.168.1.1:80"
  let tcpPacket = (IPv4Header(
    version: 4, headerLength: 5, totalLength: 40,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("10.0.0.1"),
    destIP: parseIPv4("192.168.1.1")
  ) / TCPHeader(
    sourcePort: 12345,
    destPort: 80,
    flags: TCP_SYN,
    windowSize: 65535
  ))
  echo fmt"   Size: {tcpPacket.toBytes().len} bytes"

  # UDP packet
  echo ""
  echo "2. UDP packet to 8.8.8.8:53 (DNS)"
  let udpPacket = (IPv4Header(
    version: 4, headerLength: 5, totalLength: 28,
    protocol: IPPROTO_UDP,
    sourceIP: parseIPv4("10.0.0.1"),
    destIP: parseIPv4("8.8.8.8")
  ) / UDPHeader(
    sourcePort: 54321,
    destPort: 53,
    length: 8,
    checksum: 0
  ))
  echo fmt"   Size: {udpPacket.toBytes().len} bytes"

  # ICMP packet
  echo ""
  echo "3. ICMP Echo Request to 1.1.1.1"
  let icmpPacket = (IPv4Header(
    version: 4, headerLength: 5, totalLength: 28,
    protocol: IPPROTO_ICMP,
    sourceIP: parseIPv4("10.0.0.1"),
    destIP: parseIPv4("1.1.1.1")
  ) / ICMPHeader(
    icmpType: ICMP_ECHO_REQUEST,
    code: 0,
    identifier: 1,
    sequenceNumber: 1
  ))
  echo fmt"   Size: {icmpPacket.toBytes().len} bytes"

  echo ""
  echo "All packet types built successfully!"

proc demo5_SocketOptions() =
  ## Demo 5: Setting socket options
  separator("Demo 5: Socket Options")

  echo "Demonstrating socket option configuration..."

  try:
    let sock = createTCPSocket()
    defer:
      var s = sock
      s.close()

    echo "  Socket created successfully"

    # Set IP header include
    echo "  Setting IP_HDRINCL option..."
    try:
      sock.setIPHeaderInclude(true)
      echo "    ✓ IP_HDRINCL enabled"
    except:
      echo "    ✗ Failed to set IP_HDRINCL"

    # Set receive timeout
    echo "  Setting receive timeout to 3000ms..."
    try:
      sock.setReceiveTimeout(3000)
      echo "    ✓ Receive timeout set"
    except:
      echo "    ✗ Failed to set receive timeout"

    # Set broadcast (if supported)
    echo "  Setting broadcast option..."
    try:
      sock.setBroadcast(true)
      echo "    ✓ Broadcast enabled"
    except:
      echo "    ✗ Failed to set broadcast (may not be supported)"

    echo ""
    echo "Socket options configured successfully!"

  except Exception as e:
    echo "  ✗ Error: ", e.msg

# Main demo runner
proc main() =
  # Auto-elevate to admin if needed
  elevateIfNeeded()

  randomize()

  echo "NimPacket Raw Socket Demo"
  echo "Testing with 8.8.8.8 (Google DNS) and 1.1.1.1 (Cloudflare DNS)"
  echo ""

  demo1_CheckPrivileges()
  sleepMs(500)

  demo2_ICMPPing()
  sleepMs(1000)

  demo3_TCPSyn()
  sleepMs(1000)

  demo4_BuildingPackets()
  sleepMs(500)

  demo5_SocketOptions()

  echo ""
  echo "Demo complete."

when isMainModule:
  main()
