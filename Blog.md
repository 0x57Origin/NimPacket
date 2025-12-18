# NimPacket Gets Raw Socket Support

NimPacket now includes production-grade raw socket I/O for Windows and Linux. Send and receive packets at the IP layer with full Winsock2 support.

**New Features:**
- Create raw sockets (ICMP, TCP, UDP, IP) with automatic admin elevation on Windows
- Send packets with proper error handling and cross-platform compatibility
- Receive packets with timeout support and custom filtering
- Socket options: promiscuous mode, broadcast, IP header inclusion

Check out the demo at `examples/rawsocket_demo.nim` or run the full test suite at `tests/test_rawsocket.nim`.

**Repository:** https://github.com/0x57Origin/NimPacket
