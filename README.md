# NimPacket

🌐 **Website:** https://nim-packet-website.vercel.app  
📦 **Install:** `nimble install nimpacket`  
📂 **GitHub:** https://github.com/0x57Origin/NimPacket


```
  ███╗   ██╗██╗███╗   ███╗██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
  ████╗  ██║██║████╗ ████║██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
  ██╔██╗ ██║██║██╔████╔██║██████╔╝███████║██║     █████╔╝ █████╗     ██║   
  ██║╚██╗██║██║██║╚██╔╝██║██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   
  ██║ ╚████║██║██║ ╚═╝ ██║██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   
  ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
```

A low-level packet manipulation library for Nim. Build network tools, scanners, and security applications with precise control over packet headers and data.

## What It Does

NimPacket is a packet manipulation library I built for my Masters in Cybersecurity project. It handles low-level network programming and gives you direct access to packet headers for building/parsing network packets manually.

Started this because I needed something lightweight for my research and got tired of wrestling with higher-level libraries that hide the low-level details I actually needed to work with.

## Installation

```bash
nimble install nimpacket
```

Or add to your `.nimble` file:
```nim
requires "nimpacket >= 0.1.0"
```

## Quick Example

### IPv4 Example
```nim
import nimpacket

# Create an IPv4 header
let ip = IPv4Header(
  version: 4,
  headerLength: 5,
  totalLength: 40,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.1"),
  destIP: parseIPv4("192.168.1.100")
)

# Create a TCP header
let tcp = TCPHeader(
  sourcePort: 12345,
  destPort: 80,
  flags: TCP_SYN
)

# Convert to bytes
let packet = (ip / tcp).toBytes()

# Parse bytes back to headers
let parsed = parsePacket(packet)
echo ipToString(parsed.ipv4.sourceIP)  # 192.168.1.1
```

### IPv6 Example
```nim
import nimpacket

# Create an IPv6 header
let ipv6 = IPv6Header(
  version: 6,
  payloadLength: 8,
  nextHeader: IPV6_NEXT_HEADER_ICMPV6,
  hopLimit: 64,
  sourceIP: parseIPv6("2001:db8::1"),
  destIP: parseIPv6("2001:db8::2")
)

# Create an ICMPv6 Echo Request (ping)
var icmpv6 = newICMPv6EchoRequest(1234, 1)
icmpv6.checksum = calculateICMPv6Checksum(ipv6, icmpv6, @[])

# Build and serialize packet
let packet = (ipv6 / icmpv6).toBytes()
echo "IPv6 packet size: ", packet.len  # 48 bytes
```

## Core Types

### EthernetHeader
```nim
type EthernetHeader = object
  destMAC: array[6, uint8]
  srcMAC: array[6, uint8]
  etherType: uint16
```

### ARPPacket
```nim
type ARPPacket = object
  hardwareType: uint16
  protocolType: uint16
  hardwareSize: uint8
  protocolSize: uint8
  opcode: uint16
  senderMAC: array[6, uint8]
  senderIP: uint32
  targetMAC: array[6, uint8]
  targetIP: uint32
```

### IPv4Header
```nim
type IPv4Header = object
  version: uint8
  headerLength: uint8
  totalLength: uint16
  identification: uint16
  flags: uint16
  protocol: uint8
  checksum: uint16
  sourceIP: uint32
  destIP: uint32
```

### TCPHeader  
```nim
type TCPHeader = object
  sourcePort: uint16
  destPort: uint16
  sequenceNumber: uint32
  acknowledgmentNumber: uint32
  flags: uint16
  windowSize: uint16
  checksum: uint16
  urgentPointer: uint16
```

### UDPHeader
```nim
type UDPHeader = object
  sourcePort: uint16
  destPort: uint16
  length: uint16
  checksum: uint16
```

### ICMPHeader
```nim
type ICMPHeader = object
  icmpType: uint8
  code: uint8
  checksum: uint16
  identifier: uint16
  sequenceNumber: uint16
```

### IPv6Header
```nim
type IPv6Header = object
  version: uint8
  trafficClass: uint8
  flowLabel: uint32              # 20-bit flow label
  payloadLength: uint16
  nextHeader: uint8              # 6=TCP, 17=UDP, 58=ICMPv6
  hopLimit: uint8
  sourceIP: array[16, uint8]     # 128-bit address
  destIP: array[16, uint8]       # 128-bit address
```

### ICMPv6Header
```nim
type ICMPv6Header = object
  icmpType: uint8
  code: uint8
  checksum: uint16
  messageBody: array[4, uint8]   # Type-specific data
```

## Main Functions

### Serialization
- `toBytes()` - Convert any header to byte sequence
- `IPv4Header.toBytes()`, `TCPHeader.toBytes()`, etc.

### Parsing
- `parseEthernet(data: seq[byte])` - Parse Ethernet header from bytes
- `parseARP(data: seq[byte])` - Parse ARP packet from bytes
- `parseIPv4(data: seq[byte])` - Parse IPv4 header from bytes
- `parseIPv6Header(data: seq[byte])` - Parse IPv6 header from bytes
- `parseTCP(data: seq[byte])` - Parse TCP header from bytes
- `parseUDP(data: seq[byte])` - Parse UDP header from bytes
- `parseICMP(data: seq[byte])` - Parse ICMP header from bytes
- `parseICMPv6Header(data: seq[byte])` - Parse ICMPv6 header from bytes
- `parsePacket(data: seq[byte])` - Auto-detect and parse complete packet (supports IPv4 and IPv6)

### Checksums
- `calculateIPv4Checksum(header: IPv4Header)` - Calculate IPv4 header checksum
- `calculateTCPChecksum(ip: IPv4Header, tcp: TCPHeader, data: seq[byte])` - TCP checksum with IPv4 pseudo-header
- `calculateUDPChecksum(ip: IPv4Header, udp: UDPHeader, data: seq[byte])` - UDP checksum with IPv4 pseudo-header
- `calculateICMPChecksum(icmp: ICMPHeader, data: seq[byte])` - ICMP checksum
- `calculateICMPv6Checksum(ipv6: IPv6Header, icmpv6: ICMPv6Header, data: seq[byte])` - ICMPv6 checksum with IPv6 pseudo-header

### Utilities

**MAC Address:**
- `parseMAC(mac: string)` - Convert "AA:BB:CC:DD:EE:FF" to array[6, uint8]
- `macToString(mac: array[6, uint8])` - Convert MAC to "AA:BB:CC:DD:EE:FF"
- `broadcastMAC()` - Return broadcast MAC (FF:FF:FF:FF:FF:FF)

**IPv4 Address:**
- `parseIPv4(ip: string)` - Convert "192.168.1.1" to uint32
- `ipToString(ip: uint32)` - Convert uint32 to "192.168.1.1"

**IPv6 Address:**
- `parseIPv6(ip: string)` - Convert "2001:db8::1" to array[16, uint8] (supports compressed notation)
- `ipv6ToString(ip: array[16, uint8])` - Convert to compressed string format per RFC 5952

**ARP:**
- `newARPRequest(...)` - Create ARP request packet
- `newARPReply(...)` - Create ARP reply packet

**ICMPv6:**
- `newICMPv6EchoRequest(identifier, sequence)` - Create ICMPv6 Echo Request
- `newICMPv6EchoReply(identifier, sequence)` - Create ICMPv6 Echo Reply

**Byte Order:**
- `htons(x: uint16)`, `ntohs(x: uint16)` - 16-bit network/host byte order
- `htonl(x: uint32)`, `ntohl(x: uint32)` - 32-bit network/host byte order

### Layer Stacking
- Use `/` operator to combine headers
  - `ethernet / ipv4 / tcp` - IPv4 Ethernet frame
  - `ethernet / ipv6 / tcp` - IPv6 Ethernet frame
  - `ethernet / arp` - ARP request/reply frame
  - `ipv4 / tcp / payload` - IPv4 packet with TCP
  - `ipv6 / icmpv6 / payload` - IPv6 packet with ICMPv6
- `Packet.toBytes()` - Serialize complete packet to bytes

## Raw Socket I/O

**IMPORTANT PRIVILEGE REQUIREMENTS:**
- **Windows:** Must run as Administrator
- **Linux:** Must run as root or with CAP_NET_RAW capability
- **macOS:** Must run as root

NimPacket now includes full raw socket support for sending and receiving packets at the IP layer. This allows you to actually transmit the packets you build and receive responses from the network.

### Socket Creation

```nim
# Create raw sockets for different protocols
let icmpSock = createICMPSocket()      # ICMP (ping)
let tcpSock = createTCPSocket()        # TCP
let udpSock = createUDPSocket()        # UDP
let ipSock = createIPSocket()          # All IP packets

# Generic creation
let sock = createRawSocket(AF_INET, IPPROTO_TCP)

# Always close sockets when done
defer: sock.close()
```

### Sending Packets

```nim
import nimpacket

# Build a TCP SYN packet
let packet = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 40,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.10"),
  destIP: parseIPv4("192.168.1.1")
) / TCPHeader(
  sourcePort: 12345,
  destPort: 80,
  flags: TCP_SYN
))

# Send the packet
let sock = createTCPSocket()
defer: sock.close()
sock.sendPacket(packet.toBytes(), "192.168.1.1")
```

### Receiving Packets

```nim
# Receive with timeout
let response = sock.receivePacket(timeoutMs = 5000)

if response.len > 0:
  let packet = parsePacket(response)
  echo "Received from: ", ipToString(packet.ipv4.sourceIP)
```

### Filtered Receiving

```nim
# Wait for specific packets using a filter function
let response = sock.receivePacketWithTimeout(5.0) do (data: seq[byte]) -> bool:
  let pkt = parsePacket(data)
  return pkt.ipv4.protocol == IPPROTO_ICMP and
         pkt.icmp.icmpType == ICMP_ECHO_REPLY

if response.len > 0:
  echo "Got ICMP Echo Reply!"
```

### Socket Options

```nim
# Enable IP header inclusion (for custom IP headers)
sock.setIPHeaderInclude(true)

# Set receive timeout
sock.setReceiveTimeout(3000)  # 3 seconds

# Enable broadcast
sock.setBroadcast(true)

# Enable promiscuous mode (Windows only)
sock.setPromiscuousMode(true)  # Captures all network traffic
```

### Privilege Checking

```nim
# Check if running with sufficient privileges
if not isRunningAsAdmin():
  echo "Error: This program requires administrator/root privileges"
  quit(1)
```

### Complete ICMP Ping Example

```nim
import nimpacket
import std/random

let sock = createICMPSocket()
defer: sock.close()

# Build ICMP Echo Request
var icmp = ICMPHeader(
  icmpType: ICMP_ECHO_REQUEST,
  code: 0,
  identifier: 1234,
  sequenceNumber: 1
)

let payload = "Hello, World!".toBytes()
icmp.checksum = calculateICMPChecksum(icmp, payload)

# Build IP header
var ip = IPv4Header(
  version: 4,
  headerLength: 5,
  totalLength: (20 + 8 + payload.len).uint16,
  identification: rand(65535).uint16,
  protocol: IPPROTO_ICMP,
  sourceIP: parseIPv4("192.168.1.10"),
  destIP: parseIPv4("8.8.8.8")
)

ip.checksum = calculateIPv4Checksum(ip)

# Send packet
let packet = (ip / icmp / payload).toBytes()
sock.sendPacket(packet, "8.8.8.8")

# Wait for reply
let response = sock.receivePacketWithTimeout(5.0) do (data: seq[byte]) -> bool:
  let pkt = parsePacket(data)
  return pkt.ipv4.protocol == IPPROTO_ICMP and
         pkt.icmp.icmpType == ICMP_ECHO_REPLY and
         pkt.icmp.identifier == 1234

if response.len > 0:
  echo "Ping successful!"
```

### Raw Socket Functions

**Socket Creation:**
- `createRawSocket(family, protocol)` - Create raw socket with specific family and protocol
- `createICMPSocket()` - Create ICMP socket for ping
- `createTCPSocket()` - Create TCP raw socket
- `createUDPSocket()` - Create UDP raw socket
- `createIPSocket()` - Create IP socket (receives all protocols)
- `close()` - Close socket and free resources

**Sending/Receiving:**
- `sendPacket(packet: seq[byte], destIP: string): int` - Send packet to destination
- `receivePacket(maxSize = 65535, timeoutMs = 5000): seq[byte]` - Receive packet with timeout
- `receivePacketWithTimeout(timeoutSec, filter): seq[byte]` - Receive with custom filter

**Socket Options:**
- `setIPHeaderInclude(enable: bool)` - Enable/disable IP_HDRINCL option
- `setReceiveTimeout(timeoutMs: int)` - Set receive timeout
- `setBroadcast(enable: bool)` - Enable/disable broadcast
- `setPromiscuousMode(enable: bool)` - Enable promiscuous mode (Windows only)

**Utilities:**
- `isRunningAsAdmin(): bool` - Check if process has required privileges

**Error Types:**
- `RawSocketError` - Base error type for raw socket operations
- `PrivilegeError` - Insufficient privileges (not admin/root)
- `SocketCreateError` - Failed to create socket
- `SocketSendError` - Failed to send packet
- `SocketReceiveError` - Failed to receive packet
- `SocketOptionError` - Failed to set socket option

## Constants

### EtherTypes
```nim
const
  ETHERTYPE_IPV4* = 0x0800
  ETHERTYPE_ARP* = 0x0806
  ETHERTYPE_IPV6* = 0x86DD
```

### ARP Operations
```nim
const
  ARP_REQUEST* = 1
  ARP_REPLY* = 2
  ARP_HARDWARE_ETHERNET* = 1
  ARP_PROTOCOL_IPV4* = 0x0800
```

### TCP Flags
```nim
const
  TCP_FIN* = 0x01
  TCP_SYN* = 0x02  
  TCP_RST* = 0x04
  TCP_PSH* = 0x08
  TCP_ACK* = 0x10
  TCP_URG* = 0x20
```

### Protocol Numbers
```nim
const
  IPPROTO_ICMP* = 1
  IPPROTO_TCP* = 6
  IPPROTO_UDP* = 17
  IPPROTO_ICMPV6* = 58

  # IPv6 Next Header values
  IPV6_NEXT_HEADER_TCP* = 6
  IPV6_NEXT_HEADER_UDP* = 17
  IPV6_NEXT_HEADER_ICMPV6* = 58
  IPV6_NEXT_HEADER_NO_NEXT* = 59
```

### ICMP Types
```nim
const
  ICMP_ECHO_REPLY* = 0
  ICMP_ECHO_REQUEST* = 8
  ICMP_TIME_EXCEEDED* = 11
```

### ICMPv6 Types
```nim
const
  ICMPV6_DEST_UNREACH* = 1
  ICMPV6_PACKET_TOO_BIG* = 2
  ICMPV6_TIME_EXCEEDED* = 3
  ICMPV6_ECHO_REQUEST* = 128
  ICMPV6_ECHO_REPLY* = 129
  ICMPV6_ROUTER_SOLICITATION* = 133
  ICMPV6_ROUTER_ADVERTISEMENT* = 134
  ICMPV6_NEIGHBOR_SOLICITATION* = 135
  ICMPV6_NEIGHBOR_ADVERTISEMENT* = 136
```

## Real Usage Examples

### ARP Scanner
```nim
import nimpacket

proc arpScan(network: string) =
  let myMAC = parseMAC("AA:BB:CC:DD:EE:FF")
  let myIP = parseIPv4("192.168.1.10")

  for i in 1..254:
    let targetIP = parseIPv4("192.168.1." & $i)

    let arpRequest = (EthernetHeader(
      destMAC: broadcastMAC(),
      srcMAC: myMAC,
      etherType: ETHERTYPE_ARP
    ) / newARPRequest(myMAC, myIP, targetIP))

    let packet = arpRequest.toBytes()
    # Send packet and listen for ARP replies
    echo "Scanning ", ipToString(targetIP)
```

### Complete Ethernet Frame
```nim
import nimpacket

proc buildEthernetFrame(): seq[byte] =
  let frame = (EthernetHeader(
    destMAC: parseMAC("00:11:22:33:44:55"),
    srcMAC: parseMAC("AA:BB:CC:DD:EE:FF"),
    etherType: ETHERTYPE_IPV4
  ) / IPv4Header(
    version: 4, headerLength: 5, totalLength: 40,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.10"),
    destIP: parseIPv4("192.168.1.1")
  ) / TCPHeader(
    sourcePort: 54321,
    destPort: 80,
    flags: TCP_SYN
  ))

  result = frame.toBytes()
```

### Port Scanner
```nim
import nimpacket, net

proc scanPort(target: string, port: int): bool =
  let sock = newSocket(AF_INET, SOCK_RAW, IPPROTO_TCP)
  
  let ip = IPv4Header(
    version: 4, headerLength: 5, totalLength: 40,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.10"),
    destIP: parseIPv4(target)
  )
  
  let tcp = TCPHeader(
    sourcePort: 54321,
    destPort: port.uint16,
    flags: TCP_SYN,
    windowSize: 1024
  )
  
  let packet = (ip / tcp).toBytes()
  sock.send(packet)
  
  # Read response and check for SYN+ACK
  let response = sock.recv(1024)
  let parsed = parsePacket(response)
  return (parsed.tcp.flags and (TCP_SYN or TCP_ACK)) != 0
```

### Packet Sniffer
```nim
import nimpacket

proc sniffPackets() =
  let sock = newSocket(AF_INET, SOCK_RAW, IPPROTO_IP)
  
  while true:
    let data = sock.recv(65535)
    let packet = parsePacket(data)
    
    echo "Source: ", ipToString(packet.ipv4.sourceIP)
    echo "Dest: ", ipToString(packet.ipv4.destIP)
    
    if packet.ipv4.protocol == IPPROTO_TCP:
      echo "TCP ", packet.tcp.sourcePort, " -> ", packet.tcp.destPort
```

### ICMP Ping (IPv4)
```nim
import nimpacket

proc sendPing(target: string): seq[byte] =
  let ip = IPv4Header(
    version: 4, headerLength: 5, totalLength: 28,
    protocol: IPPROTO_ICMP,
    sourceIP: parseIPv4("192.168.1.10"),
    destIP: parseIPv4(target)
  )

  let icmp = ICMPHeader(
    icmpType: ICMP_ECHO_REQUEST,
    code: 0,
    identifier: 1234,
    sequenceNumber: 1
  )

  result = (ip / icmp).toBytes()
```

### ICMPv6 Ping (IPv6)
```nim
import nimpacket

proc sendIPv6Ping(target: string): seq[byte] =
  let ipv6 = IPv6Header(
    version: 6,
    payloadLength: 8,
    nextHeader: IPV6_NEXT_HEADER_ICMPV6,
    hopLimit: 64,
    sourceIP: parseIPv6("2001:db8::1"),
    destIP: parseIPv6(target)
  )

  var icmpv6 = newICMPv6EchoRequest(1234, 1)
  icmpv6.checksum = calculateICMPv6Checksum(ipv6, icmpv6, @[])

  result = (ipv6 / icmpv6).toBytes()
```

## What I Use It For

I mainly use NimPacket for:

- Writing port scanners and network discovery tools
- Building ARP scanners and network mapping utilities
- Creating complete Ethernet frames for low-level network operations
- Building custom packet analysis utilities
- Security research and penetration testing
- Implementing network protocols from scratch
- Traffic analysis and monitoring
- **Sending and receiving raw packets with real network I/O**
- **Building complete network tools like ping, traceroute, and custom scanners**

The library handles the annoying packet format stuff and raw socket complexities so I can focus on the actual tool logic.

## Demo Programs

Check out the `examples/` folder for working demos:

```bash
# Run the demos
nim c -r examples/demo.nim              # Basic IPv4/TCP/UDP/ICMP usage
nim c -r examples/ipv6_demo.nim         # IPv6 and ICMPv6 examples
nim c -r examples/ethernet_demo.nim     # Ethernet frame examples
nim c -r examples/arp_demo.nim          # ARP protocol examples
nim c -r examples/packet_analyzer.nim   # Packet analysis tool
nim c -r examples/rawsocket_demo.nim    # Raw socket I/O demo (requires admin)
```

**demo.nim** - Basic IPv4 protocol examples:
- IPv4 header creation and serialization
- TCP, UDP, and ICMP packet construction
- Layer stacking and parsing

**ipv6_demo.nim** - IPv6 protocol examples:
- IPv6 address parsing (compressed notation support)
- ICMPv6 Echo Request/Reply (IPv6 ping)
- IPv6 with TCP and UDP
- Neighbor Discovery message types
- Complete Ethernet + IPv6 frames
- Roundtrip serialization tests

**ethernet_demo.nim** - Layer 2 examples:
- Create Ethernet headers with MAC addresses
- Build complete Layer 2 frames (Ethernet + IPv4 + TCP)
- Add payloads to Ethernet frames
- Parse and inspect Ethernet frames
- Use different EtherTypes (IPv4, IPv6, ARP)

**arp_demo.nim** - ARP protocol examples:
- Creating ARP requests and replies
- Building complete ARP frames with Ethernet
- Network scanning with ARP
- Different ARP packet types (gratuitous, standard)
- Parsing and analyzing ARP traffic

**rawsocket_demo.nim** - Raw socket I/O examples (requires admin/root):
- Privilege checking
- Creating and configuring raw sockets
- Sending ICMP Echo Requests (ping)
- Sending TCP SYN packets
- Receiving and parsing responses
- Socket options configuration
- Complete send/receive workflow with real network targets

## Testing

Run all tests:
```bash
nimble test
```

Run specific test suites:
```bash
nimble test_ethernet
nimble test_arp
nimble test_ipv4
nimble test_ipv6
nimble test_tcp
nimble test_udp
nimble test_icmp
nimble test_icmpv6
nimble test_rawsocket    # Requires admin/root privileges
nimble test_integration
```

**Note:** Raw socket tests require administrator/root privileges. Run with `sudo` on Linux or as Administrator on Windows.

## Performance Notes

Pretty fast. Headers are just structs, serialization is basically memcpy, and I optimized the checksum calculations. Parsing doesn't allocate memory unless it has to.

## Platform Support

**Tested and working on:**
- **Windows** - Full raw socket support via Winsock2 (tested on Windows 10/11)
- **Linux** - Kali Linux and other distros (requires CAP_NET_RAW or root)

**Should work on:**
- macOS (requires root privileges)
- Other Unix-like systems with POSIX socket support

**Raw socket notes:**
- Windows: Requires Administrator privileges
- Linux: Requires root or CAP_NET_RAW capability (`sudo setcap cap_net_raw+ep your_binary`)
- The library automatically detects Windows vs Unix and uses appropriate socket APIs

## GitHub Repository

https://github.com/0x57Origin/NimPacket

