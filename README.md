# NimPacket

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
echo parsed.ipv4.sourceIP  # 192.168.1.1
```

## Core Types

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
  type: uint8
  code: uint8
  checksum: uint16
  identifier: uint16
  sequenceNumber: uint16
```

## Main Functions

### Serialization
- `toBytes()` - Convert any header to byte sequence
- `IPv4Header.toBytes()`, `TCPHeader.toBytes()`, etc.

### Parsing
- `parseIPv4(data: seq[byte])` - Parse IPv4 header from bytes
- `parseTCP(data: seq[byte])` - Parse TCP header from bytes  
- `parseUDP(data: seq[byte])` - Parse UDP header from bytes
- `parseICMP(data: seq[byte])` - Parse ICMP header from bytes

### Checksums
- `calculateIPv4Checksum(header: IPv4Header)` - Calculate IPv4 header checksum
- `calculateTCPChecksum(ip: IPv4Header, tcp: TCPHeader, data: seq[byte])` - TCP checksum with pseudo-header
- `calculateUDPChecksum(ip: IPv4Header, udp: UDPHeader, data: seq[byte])` - UDP checksum with pseudo-header
- `calculateICMPChecksum(icmp: ICMPHeader, data: seq[byte])` - ICMP checksum

### Utilities
- `parseIPv4(ip: string)` - Convert "192.168.1.1" to uint32
- `ipToString(ip: uint32)` - Convert uint32 to "192.168.1.1"  
- `htons(x: uint16)`, `ntohs(x: uint16)` - Byte order conversion
- `htonl(x: uint32)`, `ntohl(x: uint32)` - Byte order conversion

### Layer Stacking
- Use `/` operator to combine headers: `ip / tcp / udp`
- `Packet.toBytes()` - Serialize complete packet to bytes

## Constants

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
```

### ICMP Types
```nim
const
  ICMP_ECHO_REPLY* = 0
  ICMP_ECHO_REQUEST* = 8
  ICMP_TIME_EXCEEDED* = 11
```

## Real Usage Examples

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

### ICMP Ping
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
    type: ICMP_ECHO_REQUEST,
    code: 0,
    identifier: 1234,
    sequenceNumber: 1
  )
  
  result = (ip / icmp).toBytes()
```

## What I Use It For

I mainly use NimPacket for:

- Writing port scanners and network discovery tools
- Building custom packet analysis utilities  
- Security research and penetration testing
- Implementing network protocols from scratch
- Traffic analysis and monitoring

The library just handles the annoying packet format stuff so I can focus on the actual logic.

## Testing

Run all tests:
```bash
nimble test
```

Run specific test suites:
```bash
nimble test_ipv4
nimble test_tcp  
nimble test_udp
nimble test_icmp
nimble test_integration
```

## Performance Notes

Pretty fast. Headers are just structs, serialization is basically memcpy, and I optimized the checksum calculations. Parsing doesn't allocate memory unless it has to.

## Platform Support

Tested on Kali Linux. Should work on other Linux distros. Windows probably works but haven't tested it.

## GitHub Repository

https://github.com/0x57Origin/NimPacket

