## NimPacket - Low-level packet manipulation library for Nim
## 
## This library provides data structures and functions for creating,
## parsing, and manipulating network packets at the byte level.

import std/[strutils, endians]

type
  # IPv4 Header Structure
  IPv4Header* = object
    version*: uint8
    headerLength*: uint8  # In 32-bit words
    typeOfService*: uint8
    totalLength*: uint16
    identification*: uint16
    flags*: uint16  # Includes fragment offset
    fragmentOffset*: uint16
    timeToLive*: uint8
    protocol*: uint8
    checksum*: uint16
    sourceIP*: uint32
    destIP*: uint32

  # TCP Header Structure
  TCPHeader* = object
    sourcePort*: uint16
    destPort*: uint16
    sequenceNumber*: uint32
    acknowledgmentNumber*: uint32
    headerLength*: uint8  # In 32-bit words
    flags*: uint16
    windowSize*: uint16
    checksum*: uint16
    urgentPointer*: uint16

  # UDP Header Structure
  UDPHeader* = object
    sourcePort*: uint16
    destPort*: uint16
    length*: uint16
    checksum*: uint16

  # ICMP Header Structure
  ICMPHeader* = object
    icmpType*: uint8
    code*: uint8
    checksum*: uint16
    identifier*: uint16
    sequenceNumber*: uint16

  # Packet composition types
  Packet* = object
    ipv4*: IPv4Header
    tcp*: TCPHeader
    udp*: UDPHeader
    icmp*: ICMPHeader
    payload*: seq[byte]

  # Exceptions
  InvalidPacketError* = object of CatchableError
  InsufficientDataError* = object of CatchableError

# Protocol constants
const
  IPPROTO_ICMP* = 1
  IPPROTO_TCP* = 6
  IPPROTO_UDP* = 17

# TCP Flag constants
const
  TCP_FIN* = 0x01
  TCP_SYN* = 0x02
  TCP_RST* = 0x04
  TCP_PSH* = 0x08
  TCP_ACK* = 0x10
  TCP_URG* = 0x20

# ICMP Type constants
const
  ICMP_ECHO_REPLY* = 0
  ICMP_DEST_UNREACH* = 3
  ICMP_REDIRECT* = 5
  ICMP_ECHO_REQUEST* = 8
  ICMP_TIME_EXCEEDED* = 11
  ICMP_PARAM_PROB* = 12
  ICMP_ROUTER_SOL* = 10
  ICMP_ROUTER_ADV* = 9

# IP Address parsing
proc parseIPv4*(ip: string): uint32 =
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(ValueError, "Invalid IP address format")
  
  result = 0
  for i, part in parts:
    let octet = parseUInt(part)
    if octet > 255:
      raise newException(ValueError, "IP octet out of range")
    result = result or (octet.uint32 shl (24 - i * 8))

proc ipToString*(ip: uint32): string =
  let a = (ip shr 24) and 0xFF
  let b = (ip shr 16) and 0xFF
  let c = (ip shr 8) and 0xFF
  let d = ip and 0xFF
  result = $a & "." & $b & "." & $c & "." & $d

# Byte order conversion
proc htons*(x: uint16): uint16 = 
  when cpuEndian == bigEndian: x
  else: (x shl 8) or (x shr 8)

proc ntohs*(x: uint16): uint16 = htons(x)

proc htonl*(x: uint32): uint32 =
  when cpuEndian == bigEndian: x
  else: ((x and 0xFF) shl 24) or (((x shr 8) and 0xFF) shl 16) or 
        (((x shr 16) and 0xFF) shl 8) or ((x shr 24) and 0xFF)

proc ntohl*(x: uint32): uint32 = htonl(x)

# Convert string to bytes
proc toBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0..<s.len:
    result[i] = s[i].byte

# Serialization functions
proc toBytes*(header: IPv4Header): seq[byte] =
  result = newSeq[byte](20)
  result[0] = (header.version shl 4) or header.headerLength
  result[1] = header.typeOfService
  bigEndian16(addr result[2], unsafeAddr header.totalLength)
  bigEndian16(addr result[4], unsafeAddr header.identification)
  bigEndian16(addr result[6], unsafeAddr header.flags)
  result[8] = header.timeToLive
  result[9] = header.protocol
  bigEndian16(addr result[10], unsafeAddr header.checksum)
  bigEndian32(addr result[12], unsafeAddr header.sourceIP)
  bigEndian32(addr result[16], unsafeAddr header.destIP)

proc toBytes*(header: TCPHeader): seq[byte] =
  result = newSeq[byte](20)
  bigEndian16(addr result[0], unsafeAddr header.sourcePort)
  bigEndian16(addr result[2], unsafeAddr header.destPort)
  bigEndian32(addr result[4], unsafeAddr header.sequenceNumber)
  bigEndian32(addr result[8], unsafeAddr header.acknowledgmentNumber)
  result[12] = (header.headerLength shl 4) or ((header.flags shr 8).uint8)
  result[13] = header.flags.uint8
  bigEndian16(addr result[14], unsafeAddr header.windowSize)
  bigEndian16(addr result[16], unsafeAddr header.checksum)
  bigEndian16(addr result[18], unsafeAddr header.urgentPointer)

proc toBytes*(header: UDPHeader): seq[byte] =
  result = newSeq[byte](8)
  bigEndian16(addr result[0], unsafeAddr header.sourcePort)
  bigEndian16(addr result[2], unsafeAddr header.destPort)
  bigEndian16(addr result[4], unsafeAddr header.length)
  bigEndian16(addr result[6], unsafeAddr header.checksum)

proc toBytes*(header: ICMPHeader): seq[byte] =
  result = newSeq[byte](8)
  result[0] = header.icmpType
  result[1] = header.code
  bigEndian16(addr result[2], unsafeAddr header.checksum)
  bigEndian16(addr result[4], unsafeAddr header.identifier)
  bigEndian16(addr result[6], unsafeAddr header.sequenceNumber)

# Parsing functions
proc parseIPv4*(data: seq[byte]): IPv4Header =
  if data.len < 20:
    raise newException(InsufficientDataError, "Not enough data for IPv4 header")
  
  result.version = data[0] shr 4
  result.headerLength = data[0] and 0x0F
  result.typeOfService = data[1]
  littleEndian16(addr result.totalLength, unsafeAddr data[2])
  result.totalLength = ntohs(result.totalLength)
  littleEndian16(addr result.identification, unsafeAddr data[4])
  result.identification = ntohs(result.identification)
  littleEndian16(addr result.flags, unsafeAddr data[6])
  result.flags = ntohs(result.flags)
  result.timeToLive = data[8]
  result.protocol = data[9]
  littleEndian16(addr result.checksum, unsafeAddr data[10])
  result.checksum = ntohs(result.checksum)
  littleEndian32(addr result.sourceIP, unsafeAddr data[12])
  result.sourceIP = ntohl(result.sourceIP)
  littleEndian32(addr result.destIP, unsafeAddr data[16])
  result.destIP = ntohl(result.destIP)

proc parseTCP*(data: seq[byte]): TCPHeader =
  if data.len < 20:
    raise newException(InsufficientDataError, "Not enough data for TCP header")
  
  littleEndian16(addr result.sourcePort, unsafeAddr data[0])
  result.sourcePort = ntohs(result.sourcePort)
  littleEndian16(addr result.destPort, unsafeAddr data[2])
  result.destPort = ntohs(result.destPort)
  littleEndian32(addr result.sequenceNumber, unsafeAddr data[4])
  result.sequenceNumber = ntohl(result.sequenceNumber)
  littleEndian32(addr result.acknowledgmentNumber, unsafeAddr data[8])
  result.acknowledgmentNumber = ntohl(result.acknowledgmentNumber)
  result.headerLength = data[12] shr 4
  result.flags = ((data[12] and 0x0F).uint16 shl 8) or data[13].uint16
  littleEndian16(addr result.windowSize, unsafeAddr data[14])
  result.windowSize = ntohs(result.windowSize)
  littleEndian16(addr result.checksum, unsafeAddr data[16])
  result.checksum = ntohs(result.checksum)
  littleEndian16(addr result.urgentPointer, unsafeAddr data[18])
  result.urgentPointer = ntohs(result.urgentPointer)

proc parseUDP*(data: seq[byte]): UDPHeader =
  if data.len < 8:
    raise newException(InsufficientDataError, "Not enough data for UDP header")
  
  littleEndian16(addr result.sourcePort, unsafeAddr data[0])
  result.sourcePort = ntohs(result.sourcePort)
  littleEndian16(addr result.destPort, unsafeAddr data[2])
  result.destPort = ntohs(result.destPort)
  littleEndian16(addr result.length, unsafeAddr data[4])
  result.length = ntohs(result.length)
  littleEndian16(addr result.checksum, unsafeAddr data[6])
  result.checksum = ntohs(result.checksum)

proc parseICMP*(data: seq[byte]): ICMPHeader =
  if data.len < 8:
    raise newException(InsufficientDataError, "Not enough data for ICMP header")
  
  result.icmpType = data[0]
  result.code = data[1]
  littleEndian16(addr result.checksum, unsafeAddr data[2])
  result.checksum = ntohs(result.checksum)
  littleEndian16(addr result.identifier, unsafeAddr data[4])
  result.identifier = ntohs(result.identifier)
  littleEndian16(addr result.sequenceNumber, unsafeAddr data[6])
  result.sequenceNumber = ntohs(result.sequenceNumber)

# Checksum functions
proc calculateChecksum(data: openArray[byte]): uint16 =
  var sum: uint32 = 0
  var i = 0
  
  # Sum 16-bit words
  while i < data.len - 1:
    sum += (data[i].uint32 shl 8) + data[i + 1].uint32
    i += 2
  
  # Add left-over byte, if any
  if i < data.len:
    sum += data[i].uint32 shl 8
  
  # Fold carry bits
  while (sum shr 16) != 0:
    sum = (sum and 0xFFFF) + (sum shr 16)
  
  result = (not sum).uint16

proc calculateIPv4Checksum*(header: IPv4Header): uint16 =
  let headerBytes = header.toBytes()
  var checksumBytes = headerBytes
  checksumBytes[10] = 0  # Clear checksum field
  checksumBytes[11] = 0
  result = calculateChecksum(checksumBytes)

proc calculateTCPChecksum*(ip: IPv4Header, tcp: TCPHeader, data: seq[byte]): uint16 =
  # TCP checksum includes a pseudo-header
  var pseudoHeader = newSeq[byte](12)
  bigEndian32(addr pseudoHeader[0], unsafeAddr ip.sourceIP)
  bigEndian32(addr pseudoHeader[4], unsafeAddr ip.destIP)
  pseudoHeader[8] = 0  # Reserved
  pseudoHeader[9] = ip.protocol
  let tcpLen = 20 + data.len
  pseudoHeader[10] = (tcpLen shr 8).byte
  pseudoHeader[11] = tcpLen.byte
  
  var tcpBytes = tcp.toBytes()
  tcpBytes[16] = 0  # Clear checksum
  tcpBytes[17] = 0
  
  let checksumData = pseudoHeader & tcpBytes & data
  result = calculateChecksum(checksumData)

proc calculateUDPChecksum*(ip: IPv4Header, udp: UDPHeader, data: seq[byte]): uint16 =
  # UDP checksum includes a pseudo-header
  var pseudoHeader = newSeq[byte](12)
  bigEndian32(addr pseudoHeader[0], unsafeAddr ip.sourceIP)
  bigEndian32(addr pseudoHeader[4], unsafeAddr ip.destIP)
  pseudoHeader[8] = 0  # Reserved
  pseudoHeader[9] = ip.protocol
  bigEndian16(addr pseudoHeader[10], unsafeAddr udp.length)
  
  var udpBytes = udp.toBytes()
  udpBytes[6] = 0  # Clear checksum
  udpBytes[7] = 0
  
  let checksumData = pseudoHeader & udpBytes & data
  let checksum = calculateChecksum(checksumData)
  # UDP checksum of 0 means no checksum
  result = if checksum == 0: 0 else: checksum

proc calculateICMPChecksum*(icmp: ICMPHeader, data: seq[byte]): uint16 =
  var icmpBytes = icmp.toBytes()
  icmpBytes[2] = 0  # Clear checksum
  icmpBytes[3] = 0
  
  let checksumData = icmpBytes & data
  result = calculateChecksum(checksumData)

# Verification functions
proc verifyIPv4Checksum*(header: IPv4Header): bool =
  let calculatedChecksum = calculateIPv4Checksum(header)
  result = header.checksum == calculatedChecksum

proc verifyTCPChecksum*(ip: IPv4Header, tcp: TCPHeader, data: seq[byte]): bool =
  let calculatedChecksum = calculateTCPChecksum(ip, tcp, data)
  result = tcp.checksum == calculatedChecksum

proc verifyUDPChecksum*(ip: IPv4Header, udp: UDPHeader, data: seq[byte]): bool =
  if udp.checksum == 0:
    return true  # No checksum
  let calculatedChecksum = calculateUDPChecksum(ip, udp, data)
  result = udp.checksum == calculatedChecksum

proc verifyICMPChecksum*(icmp: ICMPHeader, data: seq[byte]): bool =
  let calculatedChecksum = calculateICMPChecksum(icmp, data)
  result = icmp.checksum == calculatedChecksum

# Layer combination operator
proc `/`*(ip: IPv4Header, tcp: TCPHeader): Packet =
  result.ipv4 = ip
  result.tcp = tcp

proc `/`*(ip: IPv4Header, udp: UDPHeader): Packet =
  result.ipv4 = ip
  result.udp = udp

proc `/`*(ip: IPv4Header, icmp: ICMPHeader): Packet =
  result.ipv4 = ip
  result.icmp = icmp

proc `/`*(packet: Packet, data: seq[byte]): Packet =
  result = packet
  result.payload = data

# Packet serialization
proc toBytes*(packet: Packet): seq[byte] =
  result = packet.ipv4.toBytes()
  
  case packet.ipv4.protocol:
  of IPPROTO_TCP:
    result &= packet.tcp.toBytes()
  of IPPROTO_UDP:
    result &= packet.udp.toBytes()
  of IPPROTO_ICMP:
    result &= packet.icmp.toBytes()
  else:
    discard
  
  result &= packet.payload

# Complete packet parsing
proc parsePacket*(data: seq[byte]): Packet =
  if data.len < 20:
    raise newException(InsufficientDataError, "Insufficient data for packet")
  
  result.ipv4 = parseIPv4(data[0..<20])
  let headerLen = result.ipv4.headerLength * 4
  
  if data.len < headerLen.int:
    raise newException(InsufficientDataError, "Insufficient data for IP options")
  
  let protocolData = data[headerLen.int..^1]
  
  case result.ipv4.protocol:
  of IPPROTO_TCP:
    if protocolData.len >= 20:
      result.tcp = parseTCP(protocolData[0..<20])
      let tcpHeaderLen = result.tcp.headerLength * 4
      if protocolData.len > tcpHeaderLen.int:
        result.payload = protocolData[tcpHeaderLen.int..^1]
  of IPPROTO_UDP:
    if protocolData.len >= 8:
      result.udp = parseUDP(protocolData[0..<8])
      if protocolData.len > 8:
        result.payload = protocolData[8..^1]
  of IPPROTO_ICMP:
    if protocolData.len >= 8:
      result.icmp = parseICMP(protocolData[0..<8])
      if protocolData.len > 8:
        result.payload = protocolData[8..^1]
  else:
    if protocolData.len > 0:
      result.payload = protocolData