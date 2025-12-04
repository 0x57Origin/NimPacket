import unittest
import ../src/nimpacket

suite "Protocol Integration Tests":
  test "IPv4 + TCP packet construction":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 40,  # 20 IP + 20 TCP
      identification: 0x1234,
      flags: 0x4000,  # Don't fragment
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("192.168.1.10"),
      destIP: parseIPv4("192.168.1.100")
    )
    
    let tcp = TCPHeader(
      sourcePort: 12345,
      destPort: 80,
      sequenceNumber: 1000000,
      acknowledgmentNumber: 0,
      flags: TCP_SYN,
      windowSize: 65535
    )
    
    let packet = ip / tcp
    let bytes = packet.toBytes()
    
    check bytes.len == 40  # 20 + 20 bytes
    
    # Verify we can parse it back
    let parsed = parsePacket(bytes)
    check parsed.ipv4.protocol == IPPROTO_TCP
    check parsed.tcp.destPort == 80
    check parsed.tcp.flags == TCP_SYN

  test "IPv4 + UDP packet construction":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 36,  # 20 IP + 8 UDP + 8 data
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("8.8.8.8")
    )
    
    let udp = UDPHeader(
      sourcePort: 54321,
      destPort: 53,  # DNS
      length: 16,    # 8 header + 8 data
      checksum: 0
    )
    
    let payload = "testdata".toBytes()
    
    let packet = ip / udp / payload
    let bytes = packet.toBytes()
    
    check bytes.len == 36
    
    let parsed = parsePacket(bytes)
    check parsed.ipv4.protocol == IPPROTO_UDP
    check parsed.udp.destPort == 53
    check parsed.payload == payload

  test "IPv4 + ICMP packet construction":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 36,  # 20 IP + 8 ICMP + 8 data
      protocol: IPPROTO_ICMP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.254")
    )
    
    let icmp = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0,
      identifier: 1234,
      sequenceNumber: 1
    )
    
    let pingData = "pingtest".toBytes()
    
    let packet = ip / icmp / pingData
    let bytes = packet.toBytes()
    
    check bytes.len == 36
    
    let parsed = parsePacket(bytes)
    check parsed.ipv4.protocol == IPPROTO_ICMP
    check parsed.icmp.icmpType == ICMP_ECHO_REQUEST
    check parsed.icmp.identifier == 1234

  test "TCP three-way handshake simulation":
    let serverIP = parseIPv4("192.168.1.100")
    let clientIP = parseIPv4("192.168.1.10")
    
    # Step 1: Client sends SYN
    let syn = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: clientIP, destIP: serverIP
    ) / TCPHeader(
      sourcePort: 54321, destPort: 80,
      sequenceNumber: 1000, acknowledgmentNumber: 0,
      flags: TCP_SYN, windowSize: 65535
    ))
    
    # Step 2: Server responds with SYN+ACK
    let synAck = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: serverIP, destIP: clientIP
    ) / TCPHeader(
      sourcePort: 80, destPort: 54321,
      sequenceNumber: 2000, acknowledgmentNumber: 1001,  # client seq + 1
      flags: TCP_SYN or TCP_ACK, windowSize: 32768
    ))
    
    # Step 3: Client sends ACK
    let ack = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: clientIP, destIP: serverIP
    ) / TCPHeader(
      sourcePort: 54321, destPort: 80,
      sequenceNumber: 1001, acknowledgmentNumber: 2001,  # server seq + 1
      flags: TCP_ACK, windowSize: 65535
    ))
    
    # Verify the handshake sequence
    let synParsed = parsePacket(syn.toBytes())
    let synAckParsed = parsePacket(synAck.toBytes())
    let ackParsed = parsePacket(ack.toBytes())
    
    check (synParsed.tcp.flags and TCP_SYN) != 0
    check (synParsed.tcp.flags and TCP_ACK) == 0
    
    check (synAckParsed.tcp.flags and TCP_SYN) != 0
    check (synAckParsed.tcp.flags and TCP_ACK) != 0
    check synAckParsed.tcp.acknowledgmentNumber == (synParsed.tcp.sequenceNumber + 1)
    
    check (ackParsed.tcp.flags and TCP_SYN) == 0
    check (ackParsed.tcp.flags and TCP_ACK) != 0
    check ackParsed.tcp.acknowledgmentNumber == (synAckParsed.tcp.sequenceNumber + 1)

  test "DNS query over UDP simulation":
    let dnsQuery = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 60,  # 20 IP + 8 UDP + 32 DNS
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("192.168.1.10"),
      destIP: parseIPv4("8.8.8.8")
    ) / UDPHeader(
      sourcePort: 54321,
      destPort: 53,
      length: 40,  # 8 UDP + 32 DNS query
      checksum: 0
    ))
    
    # Simulate DNS query payload (simplified)
    let dnsPayload = newSeq[byte](32)
    dnsPayload[0] = 0x12  # Transaction ID high byte
    dnsPayload[1] = 0x34  # Transaction ID low byte
    dnsPayload[2] = 0x01  # Flags: standard query
    
    let packet = dnsQuery / dnsPayload
    let bytes = packet.toBytes()
    
    let parsed = parsePacket(bytes)
    check parsed.udp.destPort == 53
    check parsed.payload[0] == 0x12
    check parsed.payload[1] == 0x34

  test "ICMP ping with payload":
    let ping = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 84,  # 20 IP + 8 ICMP + 56 data
      protocol: IPPROTO_ICMP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    ) / ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 0x1234,
      sequenceNumber: 1
    ))
    
    # Standard ping payload (56 bytes)
    let pingPayload = newSeq[byte](56)
    for i in 0..<56:
      pingPayload[i] = (0x10 + (i mod 16)).byte
    
    let packet = ping / pingPayload
    let bytes = packet.toBytes()
    
    check bytes.len == 84
    
    let parsed = parsePacket(bytes)
    check parsed.icmp.icmpType == ICMP_ECHO_REQUEST
    check parsed.payload.len == 56

  test "Port scan simulation":
    let targetIP = parseIPv4("192.168.1.100")
    let sourceIP = parseIPv4("192.168.1.10")
    let ports = [22, 80, 443, 993, 3389]
    
    for port in ports:
      let scanPacket = (IPv4Header(
        version: 4, headerLength: 5, totalLength: 40,
        protocol: IPPROTO_TCP,
        sourceIP: sourceIP, destIP: targetIP
      ) / TCPHeader(
        sourcePort: 54321,
        destPort: port.uint16,
        sequenceNumber: 1000,
        acknowledgmentNumber: 0,
        flags: TCP_SYN,
        windowSize: 1024
      ))
      
      let bytes = scanPacket.toBytes()
      let parsed = parsePacket(bytes)
      
      check parsed.tcp.destPort == port.uint16
      check parsed.tcp.flags == TCP_SYN

  test "Layer stacking operator precedence":
    let ip = IPv4Header(
      version: 4, headerLength: 5, totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("1.1.1.1"),
      destIP: parseIPv4("2.2.2.2")
    )
    
    let tcp = TCPHeader(
      sourcePort: 1234, destPort: 5678,
      flags: TCP_ACK
    )
    
    let data = "test".toBytes()
    
    # Test different ways to combine layers
    let packet1 = ip / tcp / data
    let packet2 = (ip / tcp) / data
    let packet3 = ip / (tcp / data)
    
    # All should produce equivalent results
    let bytes1 = packet1.toBytes()
    let bytes2 = packet2.toBytes()
    let bytes3 = packet3.toBytes()
    
    check bytes1 == bytes2
    check bytes2 == bytes3

  test "Checksum calculation with pseudo-headers":
    let ip = IPv4Header(
      version: 4, headerLength: 5, totalLength: 44,  # 20 IP + 20 TCP + 4 data
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    let tcp = TCPHeader(
      sourcePort: 12345, destPort: 80,
      sequenceNumber: 1000, acknowledgmentNumber: 2000,
      flags: TCP_PSH or TCP_ACK,
      windowSize: 8192, checksum: 0
    )
    
    let payload = "test".toBytes()
    
    # Calculate TCP checksum with pseudo-header
    let tcpChecksum = calculateTCPChecksum(ip, tcp, payload)
    
    # Calculate UDP checksum for comparison
    let udp = UDPHeader(
      sourcePort: 12345, destPort: 80,
      length: 12,  # 8 UDP + 4 data
      checksum: 0
    )
    let udpChecksum = calculateUDPChecksum(ip, udp, payload)
    
    check tcpChecksum != 0
    check udpChecksum != 0
    check tcpChecksum != udpChecksum  # Different protocols = different checksums

  test "Large packet fragmentation simulation":
    # Simulate a large packet that would need fragmentation
    let baseIP = IPv4Header(
      version: 4, headerLength: 5,
      identification: 0x1234,
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    )
    
    # First fragment
    let fragment1 = IPv4Header(
      version: baseIP.version, headerLength: baseIP.headerLength,
      totalLength: 1500,  # MTU size
      identification: baseIP.identification,
      flags: 0x2000,  # More fragments flag
      fragmentOffset: 0,
      protocol: baseIP.protocol,
      sourceIP: baseIP.sourceIP, destIP: baseIP.destIP
    )
    
    # Last fragment
    let fragment2 = IPv4Header(
      version: baseIP.version, headerLength: baseIP.headerLength,
      totalLength: 600,   # Remaining data
      identification: baseIP.identification,
      flags: 0x0000,  # Last fragment
      fragmentOffset: 185,  # 1480 / 8 (fragment offset is in 8-byte units)
      protocol: baseIP.protocol,
      sourceIP: baseIP.sourceIP, destIP: baseIP.destIP
    )
    
    check fragment1.identification == fragment2.identification
    check (fragment1.flags and 0x2000) != 0  # More fragments
    check (fragment2.flags and 0x2000) == 0  # Last fragment

  test "Network byte order handling":
    let originalPort: uint16 = 0x1234
    let originalIP: uint32 = 0x12345678
    
    # Test port conversion
    let networkPort = htons(originalPort)
    let hostPort = ntohs(networkPort)
    check hostPort == originalPort
    
    # Test IP conversion
    let networkIP = htonl(originalIP)
    let hostIP = ntohl(networkIP)
    check hostIP == originalIP
    
    # Create packet with specific byte order values
    let header = IPv4Header(
      version: 4, headerLength: 5, totalLength: 20,
      protocol: IPPROTO_TCP,
      sourceIP: originalIP,
      destIP: originalIP
    )
    
    let bytes = header.toBytes()
    let parsed = parseIPv4(bytes)
    
    check parsed.sourceIP == originalIP
    check parsed.destIP == originalIP

  test "Complete packet roundtrip":
    # Create a complex packet
    let originalPacket = (IPv4Header(
      version: 4, headerLength: 5, totalLength: 52,
      identification: 0xABCD, flags: 0x4000,
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("203.0.113.1"),
      destIP: parseIPv4("203.0.113.2")
    ) / TCPHeader(
      sourcePort: 443, destPort: 8080,
      sequenceNumber: 0x12345678,
      acknowledgmentNumber: 0x87654321,
      flags: TCP_PSH or TCP_ACK,
      windowSize: 4096
    ))
    
    let payload = "Hello, World!".toBytes()
    let completePacket = originalPacket / payload
    
    # Serialize and parse back
    let bytes = completePacket.toBytes()
    let parsed = parsePacket(bytes)
    
    # Verify all fields survived the roundtrip
    check parsed.ipv4.identification == 0xABCD
    check parsed.ipv4.protocol == IPPROTO_TCP
    check ipToString(parsed.ipv4.sourceIP) == "203.0.113.1"
    check ipToString(parsed.ipv4.destIP) == "203.0.113.2"
    check parsed.tcp.sourcePort == 443
    check parsed.tcp.destPort == 8080
    check parsed.tcp.sequenceNumber == 0x12345678
    check parsed.tcp.acknowledgmentNumber == 0x87654321
    check parsed.tcp.flags == (TCP_PSH or TCP_ACK)
    check parsed.payload == payload