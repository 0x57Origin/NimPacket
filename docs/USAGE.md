# Usage Guide

## Install
```bash
nimble install nimpacket
```

```nim
import nimpacket
```

## Basic Stuff

### Making packets
```nim
# TCP SYN packet
let packet = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 40,
  protocol: IPPROTO_TCP,
  sourceIP: parseIPv4("192.168.1.1"),
  destIP: parseIPv4("192.168.1.100")
) / TCPHeader(
  sourcePort: 12345, destPort: 80,
  flags: TCP_SYN, windowSize: 8192
))

let bytes = packet.toBytes()
```

### Parsing packets
```nim
let packet = parsePacket(rawBytes)
echo "From: ", ipToString(packet.ipv4.sourceIP)
echo "To: ", ipToString(packet.ipv4.destIP)

if packet.ipv4.protocol == IPPROTO_TCP:
  echo "TCP port: ", packet.tcp.destPort
```

### ICMP ping
```nim
let ping = (IPv4Header(
  version: 4, headerLength: 5, totalLength: 28,
  protocol: IPPROTO_ICMP,
  sourceIP: parseIPv4("192.168.1.1"),
  destIP: parseIPv4("8.8.8.8")
) / ICMPHeader(
  icmpType: ICMP_ECHO_REQUEST, code: 0,
  identifier: 1234, sequenceNumber: 1
))
```

## Examples

### Port scanner
```nim
proc scanPort(target: string, port: int): bool =
  let syn = (IPv4Header(
    version: 4, headerLength: 5, totalLength: 40,
    protocol: IPPROTO_TCP,
    sourceIP: parseIPv4("192.168.1.10"),
    destIP: parseIPv4(target)
  ) / TCPHeader(
    sourcePort: 54321, destPort: port.uint16,
    flags: TCP_SYN, windowSize: 1024
  ))
  
  # send packet, check response...
  # return true if port open
```

### Packet sniffer
```nim
let sock = newSocket(AF_INET, SOCK_RAW, IPPROTO_IP)
while true:
  let data = sock.recv(65535)
  let packet = parsePacket(data)
  echo ipToString(packet.ipv4.sourceIP), " -> ", ipToString(packet.ipv4.destIP)
```

## Checksums
```nim
# IPv4
var ip = IPv4Header(...)
ip.checksum = calculateIPv4Checksum(ip)

# TCP (needs pseudo-header)
let tcpChecksum = calculateTCPChecksum(ip, tcp, payload)

# UDP
let udpChecksum = calculateUDPChecksum(ip, udp, payload)

# ICMP  
let icmpChecksum = calculateICMPChecksum(icmp, payload)
```

## Notes

- Need root for raw sockets
- Always calc checksums or packets get dropped
- Test on localhost first
- Handle parse errors - not all packets are valid
- Don't send malformed crap that triggers IDS

## Common mistakes I made

- Forgot checksums (packets silently dropped, drove me nuts)
- Wrong totalLength field 
- Didn't handle bad packets in parsing
- Triggered security alerts by sending garbage