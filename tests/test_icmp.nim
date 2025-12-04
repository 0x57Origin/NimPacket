import unittest
import ../src/nimpacket

suite "ICMP Header Tests":
  test "Create basic ICMP header":
    let header = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0,
      identifier: 1234,
      sequenceNumber: 1
    )
    
    check header.icmpType == ICMP_ECHO_REQUEST
    check header.code == 0
    check header.identifier == 1234
    check header.sequenceNumber == 1

  test "ICMP Echo Request/Reply":
    let echoRequest = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0,
      identifier: 0x1234,
      sequenceNumber: 42
    )
    
    let echoReply = ICMPHeader(
      icmpType: ICMP_ECHO_REPLY,
      code: 0,
      checksum: 0,
      identifier: 0x1234,  # Same as request
      sequenceNumber: 42   # Same as request
    )
    
    check echoRequest.icmpType == ICMP_ECHO_REQUEST
    check echoReply.icmpType == ICMP_ECHO_REPLY
    check echoRequest.identifier == echoReply.identifier
    check echoRequest.sequenceNumber == echoReply.sequenceNumber

  test "ICMP Time Exceeded":
    let timeExceeded = ICMPHeader(
      icmpType: ICMP_TIME_EXCEEDED,
      code: 0,  # TTL exceeded in transit
      checksum: 0,
      identifier: 0,
      sequenceNumber: 0
    )
    
    check timeExceeded.icmpType == ICMP_TIME_EXCEEDED
    check timeExceeded.code == 0

  test "ICMP Destination Unreachable":
    let destUnreach = ICMPHeader(
      icmpType: ICMP_DEST_UNREACH,
      code: 3,  # Port unreachable
      checksum: 0,
      identifier: 0,
      sequenceNumber: 0
    )
    
    check destUnreach.icmpType == ICMP_DEST_UNREACH
    check destUnreach.code == 3

  test "ICMP header serialization":
    let header = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0xABCD,
      identifier: 0x1111,
      sequenceNumber: 0x2222
    )
    
    let bytes = header.toBytes()
    check bytes.len == 8  # ICMP header is 8 bytes
    
    # Check type and code
    check bytes[0] == ICMP_ECHO_REQUEST
    check bytes[1] == 0
    
    # Check identifier and sequence (network byte order)
    check ((bytes[4].uint16 shl 8) or bytes[5].uint16) == 0x1111
    check ((bytes[6].uint16 shl 8) or bytes[7].uint16) == 0x2222

  test "ICMP header parsing":
    let original = ICMPHeader(
      icmpType: ICMP_ECHO_REPLY,
      code: 0,
      checksum: 0x5555,
      identifier: 0xDEAD,
      sequenceNumber: 0xBEEF
    )
    
    let bytes = original.toBytes()
    let parsed = parseICMP(bytes)
    
    check parsed.icmpType == original.icmpType
    check parsed.code == original.code
    check parsed.checksum == original.checksum
    check parsed.identifier == original.identifier
    check parsed.sequenceNumber == original.sequenceNumber

  test "ICMP checksum calculation":
    let icmp = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0,  # Will be calculated
      identifier: 1,
      sequenceNumber: 1
    )
    
    let payload = "ping data test".toBytes()
    let checksum = calculateICMPChecksum(icmp, payload)
    
    check checksum != 0  # Should calculate a non-zero checksum
    
    # Verify checksum
    var icmpWithChecksum = icmp
    icmpWithChecksum.checksum = checksum
    check verifyICMPChecksum(icmpWithChecksum, payload) == true

  test "ICMP ping sequence":
    # Simulate ping sequence with incrementing sequence numbers
    let ping1 = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 0x1234,
      sequenceNumber: 1
    )
    
    let ping2 = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 0x1234,  # Same process
      sequenceNumber: 2    # Next in sequence
    )
    
    let ping3 = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 0x1234,
      sequenceNumber: 3
    )
    
    check ping1.identifier == ping2.identifier
    check ping2.identifier == ping3.identifier
    check ping1.sequenceNumber == 1
    check ping2.sequenceNumber == 2
    check ping3.sequenceNumber == 3

  test "ICMP traceroute simulation":
    # Time exceeded responses for traceroute
    let hop1 = ICMPHeader(
      icmpType: ICMP_TIME_EXCEEDED,
      code: 0,  # TTL exceeded
      identifier: 0,
      sequenceNumber: 0
    )
    
    let hop2 = ICMPHeader(
      icmpType: ICMP_TIME_EXCEEDED,
      code: 0,
      identifier: 0,
      sequenceNumber: 0
    )
    
    let finalDest = ICMPHeader(
      icmpType: ICMP_DEST_UNREACH,
      code: 3,  # Port unreachable
      identifier: 0,
      sequenceNumber: 0
    )
    
    check hop1.icmpType == ICMP_TIME_EXCEEDED
    check hop2.icmpType == ICMP_TIME_EXCEEDED
    check finalDest.icmpType == ICMP_DEST_UNREACH

  test "ICMP redirect message":
    let redirect = ICMPHeader(
      icmpType: ICMP_REDIRECT,
      code: 1,  # Redirect for host
      checksum: 0,
      identifier: 0,  # Not used for redirects
      sequenceNumber: 0  # Gateway IP would go here in real implementation
    )
    
    check redirect.icmpType == ICMP_REDIRECT
    check redirect.code == 1

  test "ICMP parameter problem":
    let paramProblem = ICMPHeader(
      icmpType: ICMP_PARAM_PROB,
      code: 0,  # Pointer indicates error
      checksum: 0,
      identifier: 8,  # Pointer to problematic byte
      sequenceNumber: 0
    )
    
    check paramProblem.icmpType == ICMP_PARAM_PROB
    check paramProblem.identifier == 8  # Error at byte 8

  test "ICMP router advertisement":
    let routerAdv = ICMPHeader(
      icmpType: ICMP_ROUTER_ADV,
      code: 0,
      checksum: 0,
      identifier: 1,    # Number of addresses
      sequenceNumber: 1800  # Lifetime (30 minutes in seconds)
    )
    
    check routerAdv.icmpType == ICMP_ROUTER_ADV
    check routerAdv.sequenceNumber == 1800

  test "ICMP router solicitation":
    let routerSol = ICMPHeader(
      icmpType: ICMP_ROUTER_SOL,
      code: 0,
      checksum: 0,
      identifier: 0,
      sequenceNumber: 0
    )
    
    check routerSol.icmpType == ICMP_ROUTER_SOL

  test "ICMP with various payload sizes":
    let icmp = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      identifier: 1,
      sequenceNumber: 1
    )
    
    # Test with small payload
    let smallPayload = "test".toBytes()
    let smallChecksum = calculateICMPChecksum(icmp, smallPayload)
    check smallChecksum != 0
    
    # Test with larger payload
    var largePayload = newSeq[byte](1000)
    for i in 0..<1000:
      largePayload[i] = (i mod 256).byte
    
    let largeChecksum = calculateICMPChecksum(icmp, largePayload)
    check largeChecksum != 0
    check largeChecksum != smallChecksum  # Different payloads = different checksums

  test "ICMP error message format":
    # ICMP error messages include original packet info
    let error = ICMPHeader(
      icmpType: ICMP_DEST_UNREACH,
      code: 1,  # Host unreachable
      checksum: 0,
      identifier: 0,  # Unused, must be zero
      sequenceNumber: 0  # Unused, must be zero  
    )
    
    check error.identifier == 0
    check error.sequenceNumber == 0

  test "ICMP roundtrip serialization":
    let original = ICMPHeader(
      icmpType: ICMP_ECHO_REQUEST,
      code: 0,
      checksum: 0xCAFE,
      identifier: 0xBABE,
      sequenceNumber: 0xFACE
    )
    
    let bytes1 = original.toBytes()
    let parsed = parseICMP(bytes1)
    let bytes2 = parsed.toBytes()
    
    check bytes1 == bytes2