# Package

version       = "0.1.0"
author        = "NimPacket Contributors"
description   = "Low-level packet manipulation library for Nim"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 1.6.0"

# Tasks

task test, "Run all tests":
  exec "nim c -r tests/test_ipv4.nim"
  exec "nim c -r tests/test_tcp.nim"
  exec "nim c -r tests/test_udp.nim"
  exec "nim c -r tests/test_icmp.nim"
  exec "nim c -r tests/test_ethernet.nim"
  exec "nim c -r tests/test_arp.nim"
  exec "nim c -r tests/test_ipv6.nim"
  exec "nim c -r tests/test_icmpv6.nim"
  exec "nim c -r tests/test_integration.nim"

task test_ipv4, "Run IPv4 tests":
  exec "nim c -r tests/test_ipv4.nim"

task test_tcp, "Run TCP tests":
  exec "nim c -r tests/test_tcp.nim"

task test_udp, "Run UDP tests":
  exec "nim c -r tests/test_udp.nim"

task test_icmp, "Run ICMP tests":
  exec "nim c -r tests/test_icmp.nim"

task test_ethernet, "Run Ethernet tests":
  exec "nim c -r tests/test_ethernet.nim"

task test_arp, "Run ARP tests":
  exec "nim c -r tests/test_arp.nim"

task test_ipv6, "Run IPv6 tests":
  exec "nim c -r tests/test_ipv6.nim"

task test_icmpv6, "Run ICMPv6 tests":
  exec "nim c -r tests/test_icmpv6.nim"

task test_rawsocket, "Run raw socket tests (requires admin/root)":
  exec "nim c -r tests/test_rawsocket.nim"

task test_integration, "Run integration tests":
  exec "nim c -r tests/test_integration.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --git.url:https://github.com/0x57Origin/NimPacket --outdir:docs src/nimpacket.nim"

task examples, "Build examples":
  exec "nim c -d:release examples/scanner.nim"
  exec "nim c -d:release examples/packet_builder.nim"