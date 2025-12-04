import unittest
import ../src/nimpacket

suite "IPv4 Header Tests":
  test "Create basic IPv4 header":
    let header = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 20,
      identification: 12345,
      flags: 0x4000,  # Don't fragment
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.100")
    )
    
    check header.version == 4
    check header.headerLength == 5
    check header.totalLength == 20
    check header.protocol == IPPROTO_TCP
    check ipToString(header.sourceIP) == "192.168.1.1"
    check ipToString(header.destIP) == "192.168.1.100"

  test "IPv4 address parsing":
    let ip1 = parseIPv4("127.0.0.1")
    let ip2 = parseIPv4("255.255.255.255")
    let ip3 = parseIPv4("10.0.0.1")
    
    check ipToString(ip1) == "127.0.0.1"
    check ipToString(ip2) == "255.255.255.255"
    check ipToString(ip3) == "10.0.0.1"

  test "IPv4 header serialization":
    let header = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 20,
      identification: 0x1234,
      flags: 0x4000,
      protocol: IPPROTO_ICMP,
      checksum: 0,  # Will be calculated
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    let bytes = header.toBytes()
    check bytes.len == 20  # Standard IPv4 header length
    
    # Check version and header length in first byte
    check (bytes[0] shr 4) == 4  # Version
    check (bytes[0] and 0x0F) == 5  # Header length
    
    # Check protocol
    check bytes[9] == IPPROTO_ICMP

  test "IPv4 header parsing":
    # Create a header, serialize it, then parse it back
    let original = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 28,
      identification: 0x5678,
      flags: 0x0000,
      protocol: IPPROTO_UDP,
      sourceIP: parseIPv4("172.16.0.1"),
      destIP: parseIPv4("172.16.0.254")
    )
    
    let bytes = original.toBytes()
    let parsed = parseIPv4(bytes)
    
    check parsed.version == original.version
    check parsed.headerLength == original.headerLength
    check parsed.totalLength == original.totalLength
    check parsed.identification == original.identification
    check parsed.protocol == original.protocol
    check parsed.sourceIP == original.sourceIP
    check parsed.destIP == original.destIP

  test "IPv4 checksum calculation":
    let header = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 20,
      identification: 0,
      flags: 0x4000,  # Don't fragment
      protocol: IPPROTO_ICMP,
      checksum: 0,
      sourceIP: parseIPv4("192.168.1.1"),
      destIP: parseIPv4("192.168.1.2")
    )
    
    let checksum = calculateIPv4Checksum(header)
    check checksum != 0  # Should calculate a non-zero checksum
    
    # Verify checksum by creating header with calculated checksum
    # and ensuring validation passes
    var headerWithChecksum = header
    headerWithChecksum.checksum = checksum
    check verifyIPv4Checksum(headerWithChecksum) == true

  test "IPv4 header with options":
    # Test header with options (headerLength > 5)
    let header = IPv4Header(
      version: 4,
      headerLength: 6,  # 24 bytes total (20 + 4 options)
      totalLength: 24,
      identification: 1,
      flags: 0,
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("1.1.1.1"),
      destIP: parseIPv4("8.8.8.8")
    )
    
    check header.headerLength == 6
    check header.totalLength == 24

  test "IPv4 fragmentation flags":
    let header1 = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 1500,
      flags: 0x0000,  # May fragment
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    let header2 = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 1500,
      flags: 0x4000,  # Don't fragment
      protocol: IPPROTO_TCP,
      sourceIP: parseIPv4("10.0.0.1"),
      destIP: parseIPv4("10.0.0.2")
    )
    
    check (header1.flags and 0x4000) == 0  # May fragment
    check (header2.flags and 0x4000) != 0  # Don't fragment

  test "IPv4 roundtrip serialization":
    # Test that serialize -> parse -> serialize produces identical results
    let original = IPv4Header(
      version: 4,
      headerLength: 5,
      totalLength: 60,
      identification: 0xABCD,
      flags: 0x4000,
      protocol: IPPROTO_TCP,
      checksum: 0x1234,
      sourceIP: parseIPv4("203.0.113.1"),
      destIP: parseIPv4("203.0.113.254")
    )
    
    let bytes1 = original.toBytes()
    let parsed = parseIPv4(bytes1)
    let bytes2 = parsed.toBytes()
    
    check bytes1 == bytes2