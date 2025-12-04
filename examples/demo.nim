import ../src/nimpacket
import std/[strformat, strutils]

echo "NimPacket Demo - Building and Parsing Network Packets"
echo repeat("=", 50)

# Demo 1: Create an IPv4 header
echo "\n1. Creating IPv4 header:"
let ipv4 = IPv4Header(
  version: 4,
  headerLength: 5,
  totalLength: 40,  # 20 IP + 20 TCP
  identification: 12345,
  flags: 0x4000,    # Don't fragment
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.10"),
  destIP: parseIPv4("192.168.1.100")
)

echo fmt"   Source IP: {ipToString(ipv4.sourceIP)}"
echo fmt"   Dest IP: {ipToString(ipv4.destIP)}"
echo fmt"   Protocol: {ipv4.protocol} (TCP)"
echo fmt"   Total Length: {ipv4.totalLength} bytes"

# Demo 2: Create a TCP header
echo "\n2. Creating TCP header:"
let tcp = TCPHeader(
  sourcePort: 54321,
  destPort: 80,
  sequenceNumber: 1000000,
  acknowledgmentNumber: 0,
  flags: TCP_SYN,
  windowSize: 65535
)

echo fmt"   Source Port: {tcp.sourcePort}"
echo fmt"   Dest Port: {tcp.destPort} (HTTP)"
echo fmt"   Flags: SYN"
echo fmt"   Sequence: {tcp.sequenceNumber}"

# Demo 3: Combine headers into a packet
echo "\n3. Combining headers into packet:"
let packet = ipv4 / tcp
let packetBytes = packet.toBytes()

echo fmt"   Packet size: {packetBytes.len} bytes"
echo fmt"   First 20 bytes (hex): "
for i in 0..<min(20, packetBytes.len):
  if i mod 4 == 0:
    stdout.write("   ")
  stdout.write(fmt"{packetBytes[i]:02x} ")
  if (i + 1) mod 4 == 0:
    stdout.write("\n")

# Demo 4: Parse the packet back
echo "\n4. Parsing packet back:"
let parsed = parsePacket(packetBytes)
echo fmt"   Parsed Source IP: {ipToString(parsed.ipv4.sourceIP)}"
echo fmt"   Parsed Dest IP: {ipToString(parsed.ipv4.destIP)}"
echo fmt"   Parsed Source Port: {parsed.tcp.sourcePort}"
echo fmt"   Parsed Dest Port: {parsed.tcp.destPort}"
echo fmt"   Parsed TCP Flags: {parsed.tcp.flags} (SYN = {TCP_SYN})"

# Demo 5: Calculate checksums
echo "\n5. Calculating checksums:"
let ipChecksum = calculateIPv4Checksum(ipv4)
let tcpChecksum = calculateTCPChecksum(ipv4, tcp, @[])
echo fmt"   IPv4 Checksum: 0x{ipChecksum:04x}"
echo fmt"   TCP Checksum: 0x{tcpChecksum:04x}"

# Demo 6: Create different packet types
echo "\n6. Creating different packet types:"

# UDP packet
let udp = UDPHeader(
  sourcePort: 53,
  destPort: 12345,
  length: 8,  # Header only
  checksum: 0
)
let udpPacket = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 28,
  protocol: IPPROTO_UDP,
  sourceIP: parseIPv4("8.8.8.8"),
  destIP: parseIPv4("192.168.1.10")
) / udp)

echo fmt"   UDP: DNS server -> client"
echo fmt"   UDP packet size: {udpPacket.toBytes().len} bytes"

# ICMP packet
let icmp = ICMPHeader(
  icmpType: ICMP_ECHO_REQUEST,
  code: 0,
  identifier: 1234,
  sequenceNumber: 1
)
let icmpPacket = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 28,
  protocol: IPPROTO_ICMP,
  sourceIP: parseIPv4("192.168.1.1"),
  destIP: parseIPv4("8.8.8.8")
) / icmp)

echo fmt"   ICMP: Ping request to Google DNS"
echo fmt"   ICMP packet size: {icmpPacket.toBytes().len} bytes"

echo "\n" & repeat("=", 50)
echo "Demo complete! NimPacket is working correctly."