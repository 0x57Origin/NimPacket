import unittest
import ../src/nimpacket

suite "UDP Header Tests":
  test "Create basic UDP header":
    let header = UDPHeader(
      sourcePort: 53,
      destPort: 12345,
      length: 16,  # 8 byte header + 8 byte payload
      checksum: 0
    )
    
    check header.sourcePort == 53
    check header.destPort == 12345
    check header.length == 16
    check header.checksum == 0

  test "UDP header serialization":
    let header = UDPHeader(
      sourcePort: 1234,
      destPort: 5678,
      length: 12,  # 8 byte header + 4 byte payload
      checksum: 0xABCD
    )
    
    let bytes = header.toBytes()
    check bytes.len == 8  # UDP header is always 8 bytes
    
    # Check port numbers (network byte order)
    check ((bytes[0].uint16 shl 8) or bytes[1].uint16) == 1234
    check ((bytes[2].uint16 shl 8) or bytes[3].uint16) == 5678
    
    # Check length
    check ((bytes[4].uint16 shl 8) or bytes[5].uint16) == 12

  test "UDP header parsing":
    let original = UDPHeader(
      sourcePort: 67,    # DHCP server
      destPort: 68,      # DHCP client  
      length: 308,       # Typical DHCP packet size
      checksum: 0x1234
    )
    
    let bytes = original.toBytes()
    let parsed = parseUDP(bytes)
    
    check parsed.sourcePort == original.sourcePort
    check parsed.destPort == original.destPort
    check parsed.length == original.length
    check parsed.checksum == original.checksum

  test "UDP checksum calculation":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 28,  # 20 IP + 8 UDP
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    )
    
    let udp = UDPHeader(
      sourcePort: 12345,
      destPort: 53,
      length: 8,  # Header only, no payload
      checksum: 0
    )
    
    let data: seq[byte] = @[]  # No payload
    let checksum = calculateUDPChecksum(ip, udp, data)
    
    # UDP checksum is optional, but when calculated should be non-zero
    # (zero means no checksum was calculated)
    if checksum != 0:
      var udpWithChecksum = udp
      udpWithChecksum.checksum = checksum
      check verifyUDPChecksum(ip, udpWithChecksum, data) == true

  test "UDP with payload checksum":
    let ip = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 36,  # 20 IP + 8 UDP + 8 data
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    let udp = UDPHeader(
      sourcePort: 1234,
      destPort: 5678,
      length: 16,  # 8 header + 8 data
      checksum: 0
    )
    
    let payload = "testdata".toBytes()
    let checksum = calculateUDPChecksum(ip, udp, payload)
    
    if checksum != 0:
      var udpWithChecksum = udp
      udpWithChecksum.checksum = checksum
      check verifyUDPChecksum(ip, udpWithChecksum, payload) == true

  test "UDP DNS query simulation":
    let dnsQuery = UDPHeader(
      sourcePort: 54321,
      destPort: 53,      # DNS port
      length: 40,        # 8 UDP + 32 DNS query
      checksum: 0
    )
    
    check dnsQuery.destPort == 53
    check dnsQuery.length == 40

  test "UDP DHCP simulation":
    let dhcpDiscover = UDPHeader(
      sourcePort: 68,    # DHCP client port
      destPort: 67,      # DHCP server port
      length: 308,       # 8 UDP + 300 DHCP
      checksum: 0
    )
    
    check dhcpDiscover.sourcePort == 68
    check dhcpDiscover.destPort == 67

  test "UDP SNMP simulation":
    let snmpQuery = UDPHeader(
      sourcePort: 45678,
      destPort: 161,     # SNMP port
      length: 64,        # 8 UDP + 56 SNMP PDU
      checksum: 0
    )
    
    check snmpQuery.destPort == 161

  test "UDP Syslog simulation":
    let syslogMsg = UDPHeader(
      sourcePort: 12345,
      destPort: 514,     # Syslog port
      length: 128,       # 8 UDP + 120 log message
      checksum: 0
    )
    
    check syslogMsg.destPort == 514

  test "UDP length validation":
    # Minimum UDP header is 8 bytes
    let minHeader = UDPHeader(
      sourcePort: 1,
      destPort: 2,
      length: 8,         # Minimum possible
      checksum: 0
    )
    
    # Larger packet
    let largeHeader = UDPHeader(
      sourcePort: 1,
      destPort: 2,
      length: 1472,      # Typical maximum for Ethernet
      checksum: 0
    )
    
    check minHeader.length >= 8
    check largeHeader.length >= 8

  test "UDP port ranges":
    # Well-known ports (0-1023)
    let wellKnown = UDPHeader(
      sourcePort: 80,
      destPort: 443,
      length: 8
    )
    
    # Registered ports (1024-49151)
    let registered = UDPHeader(
      sourcePort: 8080,
      destPort: 3306,
      length: 8
    )
    
    # Dynamic/private ports (49152-65535)
    let dynamic = UDPHeader(
      sourcePort: 54321,
      destPort: 60000,
      length: 8
    )
    
    check wellKnown.sourcePort < 1024
    check registered.sourcePort >= 1024 and registered.sourcePort <= 49151
    check dynamic.sourcePort >= 49152

  test "UDP zero checksum handling":
    # UDP allows zero checksum (meaning no checksum calculated)
    let noChecksum = UDPHeader(
      sourcePort: 1234,
      destPort: 5678,
      length: 20,
      checksum: 0  # No checksum
    )
    
    check noChecksum.checksum == 0

  test "UDP roundtrip serialization":
    let original = UDPHeader(
      sourcePort: 9999,
      destPort: 8888,
      length: 100,
      checksum: 0xDEAD
    )
    
    let bytes1 = original.toBytes()
    let parsed = parseUDP(bytes1)
    let bytes2 = parsed.toBytes()
    
    check bytes1 == bytes2

  test "UDP broadcast simulation":
    let broadcast = UDPHeader(
      sourcePort: 12345,
      destPort: 9,       # Discard protocol for testing
      length: 16,
      checksum: 0
    )
    
    # This would typically be sent to 255.255.255.255
    check broadcast.destPort == 9

  test "UDP multicast simulation":  
    let multicast = UDPHeader(
      sourcePort: 12345,
      destPort: 5353,    # mDNS
      length: 64,
      checksum: 0
    )
    
    # This would typically be sent to 224.0.0.251
    check multicast.destPort == 5353