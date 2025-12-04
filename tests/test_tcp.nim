import unittest
import ../src/nimpacket

suite "TCP Header Tests":
  test "Create basic TCP header":
    let header = TCPHeader(
      sourcePort: 12345,
      destPort: 80,
      sequenceNumber: 1000000,
      acknowledgmentNumber: 0,
      flags: TCP_SYN,
      windowSize: 65535,
      checksum: 0,
      urgentPointer: 0
    )
    
    check header.sourcePort == 12345
    check header.destPort == 80
    check header.sequenceNumber == 1000000
    check header.acknowledgmentNumber == 0
    check header.flags == TCP_SYN
    check header.windowSize == 65535

  test "TCP flags combinations":
    let synHeader = TCPHeader(
      sourcePort: 1234,
      destPort: 5678,
      flags: TCP_SYN
    )
    
    let synAckHeader = TCPHeader(
      sourcePort: 1234, 
      destPort: 5678,
      flags: TCP_SYN or TCP_ACK
    )
    
    let finAckHeader = TCPHeader(
      sourcePort: 1234,
      destPort: 5678,
      flags: TCP_FIN or TCP_ACK
    )
    
    let rstHeader = TCPHeader(
      sourcePort: 1234,
      destPort: 5678,
      flags: TCP_RST
    )
    
    check (synHeader.flags and TCP_SYN) != 0
    check (synHeader.flags and TCP_ACK) == 0
    
    check (synAckHeader.flags and TCP_SYN) != 0
    check (synAckHeader.flags and TCP_ACK) != 0
    
    check (finAckHeader.flags and TCP_FIN) != 0
    check (finAckHeader.flags and TCP_ACK) != 0
    check (finAckHeader.flags and TCP_SYN) == 0
    
    check (rstHeader.flags and TCP_RST) != 0

  test "TCP header serialization":
    let header = TCPHeader(
      sourcePort: 443,
      destPort: 54321,
      sequenceNumber: 0x12345678,
      acknowledgmentNumber: 0x87654321,
      flags: TCP_PSH or TCP_ACK,
      windowSize: 8192,
      checksum: 0xABCD,
      urgentPointer: 0
    )
    
    let bytes = header.toBytes()
    check bytes.len == 20  # Minimum TCP header length
    
    # Check port numbers (network byte order)
    check ((bytes[0].uint16 shl 8) or bytes[1].uint16) == 443
    check ((bytes[2].uint16 shl 8) or bytes[3].uint16) == 54321

  test "TCP header parsing":
    let original = TCPHeader(
      sourcePort: 8080,
      destPort: 3306,
      sequenceNumber: 0x11111111,
      acknowledgmentNumber: 0x22222222,
      flags: TCP_SYN or TCP_ACK,
      windowSize: 16384,
      checksum: 0x5555,
      urgentPointer: 100
    )
    
    let bytes = original.toBytes()
    let parsed = parseTCP(bytes)
    
    check parsed.sourcePort == original.sourcePort
    check parsed.destPort == original.destPort
    check parsed.sequenceNumber == original.sequenceNumber
    check parsed.acknowledgmentNumber == original.acknowledgmentNumber
    check parsed.flags == original.flags
    check parsed.windowSize == original.windowSize
    check parsed.urgentPointer == original.urgentPointer

  test "TCP checksum calculation":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 40,
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    )
    
    let tcp = TCPHeader(
      sourcePort: 12345,
      destPort: 80,
      sequenceNumber: 1000,
      acknowledgmentNumber: 0,
      flags: TCP_SYN,
      windowSize: 1024,
      checksum: 0  # Will be calculated
    )
    
    let data: seq[byte] = @[]  # No payload
    let checksum = calculateTCPChecksum(ip, tcp, data)
    
    check checksum != 0  # Should calculate a non-zero checksum
    
    # Verify checksum
    var tcpWithChecksum = tcp
    tcpWithChecksum.checksum = checksum
    check verifyTCPChecksum(ip, tcpWithChecksum, data) == true

  test "TCP with payload checksum":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 52,  # 20 IP + 20 TCP + 12 data
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    let tcp = TCPHeader(
      sourcePort: 80,
      destPort: 8080,
      sequenceNumber: 500,
      acknowledgmentNumber: 1000,
      flags: TCP_PSH or TCP_ACK,
      windowSize: 2048
    )
    
    let payload = "Hello World!".toBytes()
    let checksum = calculateTCPChecksum(ip, tcp, payload)
    
    check checksum != 0
    
    var tcpWithChecksum = tcp
    tcpWithChecksum.checksum = checksum
    check verifyTCPChecksum(ip, tcpWithChecksum, payload) == true

  test "TCP connection states simulation":
    # SYN
    let syn = TCPHeader(
      sourcePort: 45678,
      destPort: 22,
      sequenceNumber: 100,
      acknowledgmentNumber: 0,
      flags: TCP_SYN,
      windowSize: 65535
    )
    
    # SYN+ACK  
    let synAck = TCPHeader(
      sourcePort: 22,
      destPort: 45678,
      sequenceNumber: 200,
      acknowledgmentNumber: 101,  # syn.seq + 1
      flags: TCP_SYN or TCP_ACK,
      windowSize: 32768
    )
    
    # ACK
    let ack = TCPHeader(
      sourcePort: 45678,
      destPort: 22,
      sequenceNumber: 101,  # syn.seq + 1
      acknowledgmentNumber: 201,  # synAck.seq + 1
      flags: TCP_ACK,
      windowSize: 65535
    )
    
    check (syn.flags and TCP_SYN) != 0
    check (syn.flags and TCP_ACK) == 0
    check synAck.acknowledgmentNumber == (syn.sequenceNumber + 1)
    
    check (synAck.flags and TCP_SYN) != 0
    check (synAck.flags and TCP_ACK) != 0
    check ack.acknowledgmentNumber == (synAck.sequenceNumber + 1)
    
    check (ack.flags and TCP_SYN) == 0
    check (ack.flags and TCP_ACK) != 0

  test "TCP header with options":
    # Simulate TCP header with maximum segment size option
    let header = TCPHeader(
      sourcePort: 80,
      destPort: 443,
      sequenceNumber: 1,
      acknowledgmentNumber: 1,
      flags: TCP_SYN,
      windowSize: 65535,
      headerLength: 6  # 24 bytes (20 base + 4 options)
    )
    
    check header.headerLength == 6

  test "TCP urgent pointer usage":
    let header = TCPHeader(
      sourcePort: 21,
      destPort: 12345,
      sequenceNumber: 1000,
      acknowledgmentNumber: 2000,
      flags: TCP_PSH or TCP_ACK or TCP_URG,
      windowSize: 1024,
      urgentPointer: 10  # Points to urgent data
    )
    
    check (header.flags and TCP_URG) != 0
    check header.urgentPointer == 10

  test "TCP window scaling":
    let smallWindow = TCPHeader(
      sourcePort: 80,
      destPort: 8080,
      windowSize: 1024
    )
    
    let largeWindow = TCPHeader(
      sourcePort: 80,
      destPort: 8080,
      windowSize: 65535
    )
    
    check smallWindow.windowSize == 1024
    check largeWindow.windowSize == 65535

  test "TCP roundtrip serialization":
    let original = TCPHeader(
      sourcePort: 443,
      destPort: 12345,
      sequenceNumber: 0xDEADBEEF,
      acknowledgmentNumber: 0xCAFEBABE,
      flags: TCP_FIN or TCP_ACK,
      windowSize: 4096,
      checksum: 0x1234,
      urgentPointer: 0
    )
    
    let bytes1 = original.toBytes()
    let parsed = parseTCP(bytes1)
    let bytes2 = parsed.toBytes()
    
    check bytes1 == bytes2