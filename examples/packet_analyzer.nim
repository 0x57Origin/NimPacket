import ../src/nimpacket
import std/[strformat, strutils]

proc analyzePacket(name: string, packetBytes: seq[byte]) =
  echo fmt"\n--- {name} ---"
  echo fmt"Raw packet size: {packetBytes.len} bytes"
  
  try:
    let packet = parsePacket(packetBytes)
    
    # Analyze IP header
    echo fmt"IPv4 Header:"
    echo fmt"  Version: {packet.ipv4.version}"
    echo fmt"  Header Length: {packet.ipv4.headerLength * 4} bytes"
    echo fmt"  Total Length: {packet.ipv4.totalLength} bytes"
    echo fmt"  Protocol: {packet.ipv4.protocol}"
    echo fmt"  Source: {ipToString(packet.ipv4.sourceIP)}"
    echo fmt"  Destination: {ipToString(packet.ipv4.destIP)}"
    
    # Analyze transport layer
    case packet.ipv4.protocol:
    of IPPROTO_TCP:
      echo fmt"TCP Header:"
      echo fmt"  Source Port: {packet.tcp.sourcePort}"
      echo fmt"  Dest Port: {packet.tcp.destPort}"
      echo fmt"  Sequence: {packet.tcp.sequenceNumber}"
      echo fmt"  Acknowledgment: {packet.tcp.acknowledgmentNumber}"
      echo fmt"  Flags: {packet.tcp.flags:02x}"
      if (packet.tcp.flags and TCP_SYN) != 0: echo "    - SYN"
      if (packet.tcp.flags and TCP_ACK) != 0: echo "    - ACK"
      if (packet.tcp.flags and TCP_FIN) != 0: echo "    - FIN"
      if (packet.tcp.flags and TCP_RST) != 0: echo "    - RST"
      if (packet.tcp.flags and TCP_PSH) != 0: echo "    - PSH"
      if (packet.tcp.flags and TCP_URG) != 0: echo "    - URG"
      echo fmt"  Window Size: {packet.tcp.windowSize}"
      
    of IPPROTO_UDP:
      echo fmt"UDP Header:"
      echo fmt"  Source Port: {packet.udp.sourcePort}"
      echo fmt"  Dest Port: {packet.udp.destPort}"
      echo fmt"  Length: {packet.udp.length}"
      
    of IPPROTO_ICMP:
      echo fmt"ICMP Header:"
      echo fmt"  Type: {packet.icmp.icmpType}"
      echo fmt"  Code: {packet.icmp.code}"
      case packet.icmp.icmpType:
      of ICMP_ECHO_REQUEST:
        echo "    - Echo Request (Ping)"
      of ICMP_ECHO_REPLY:
        echo "    - Echo Reply (Pong)"
      of ICMP_DEST_UNREACH:
        echo "    - Destination Unreachable"
      of ICMP_TIME_EXCEEDED:
        echo "    - Time Exceeded"
      else:
        echo fmt"    - Unknown type {packet.icmp.icmpType}"
      echo fmt"  Identifier: {packet.icmp.identifier}"
      echo fmt"  Sequence: {packet.icmp.sequenceNumber}"
    
    else:
      echo fmt"Unknown protocol: {packet.ipv4.protocol}"
    
    if packet.payload.len > 0:
      echo fmt"Payload: {packet.payload.len} bytes"
      if packet.payload.len <= 32:
        stdout.write("  Data: ")
        for b in packet.payload:
          if b >= 32 and b <= 126:  # Printable ASCII
            stdout.write(chr(b))
          else:
            stdout.write(".")
        echo ""
    
  except Exception as e:
    echo fmt"Error parsing packet: {e.msg}"

echo "NimPacket - Packet Analyzer Demo"
echo repeat("=", 40)

# Demo 1: TCP SYN packet (like from port scanner)
let tcpSyn = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 40,
  identification: 1337, flags: 0x4000,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("10.0.0.100"),
  destIP: parseIPv4("192.168.1.50")
) / TCPHeader(
  sourcePort: 54321, destPort: 22,
  sequenceNumber: 1000000, acknowledgmentNumber: 0,
  flags: TCP_SYN, windowSize: 8192
))

analyzePacket("TCP SYN to SSH", tcpSyn.toBytes())

# Demo 2: HTTP response packet
let httpResponse = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 52,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("93.184.216.34"),  # example.com
  destIP: parseIPv4("192.168.1.100")
) / TCPHeader(
  sourcePort: 80, destPort: 54321,
  sequenceNumber: 2000000, acknowledgmentNumber: 1001,
  flags: TCP_PSH or TCP_ACK, windowSize: 4096
) / "HTTP/1.1 200".toBytes())

analyzePacket("HTTP Response", httpResponse.toBytes())

# Demo 3: DNS Query
let dnsQuery = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 40,
  protocol: IPPROTO_UDP,
  sourceIP: parseIPv4("192.168.1.10"),
  destIP: parseIPv4("8.8.8.8")
) / UDPHeader(
  sourcePort: 55555, destPort: 53,
  length: 20, checksum: 0
) / @[0x12'u8, 0x34, 0x01, 0x00])

analyzePacket("DNS Query to Google", dnsQuery.toBytes())

# Demo 4: Ping packet
let ping = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 36,
  protocol: IPPROTO_ICMP,
  sourceIP: parseIPv4("192.168.1.1"),
  destIP: parseIPv4("1.1.1.1")
) / ICMPHeader(
  icmpType: ICMP_ECHO_REQUEST, code: 0,
  identifier: 12345, sequenceNumber: 1
) / "pingdata".toBytes())

analyzePacket("Ping to Cloudflare DNS", ping.toBytes())

echo "\n" & repeat("=", 40)
echo "Analysis complete! Try running:"
echo "  nim c -r examples/packet_analyzer.nim"