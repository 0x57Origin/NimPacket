## Raw Socket Operations for NimPacket
##
## This module provides cross-platform raw socket functionality for sending and
## receiving network packets at the IP layer.
##
## **IMPORTANT PRIVILEGE REQUIREMENTS:**
## - Windows: Must run as Administrator
## - Linux: Must run as root or have CAP_NET_RAW capability
## - macOS: Must run as root
##
## **SAFETY WARNING:**
## Raw sockets allow you to send arbitrary network packets. Use responsibly:
## - Only use for authorized security testing, research, or legitimate network tools
## - Be aware of applicable laws and regulations
## - Test only on networks you own or have explicit permission to test
## - Use rate limiting to avoid network disruption
##
## Example usage:
## ```nim
## import rawsocket, nimpacket
##
## # Create a raw socket
## let sock = createRawSocket(AF_INET, IPPROTO_TCP)
## defer: sock.close()
##
## # Build a packet
## let packet = (IPv4Header(...) / TCPHeader(...)).toBytes()
##
## # Send the packet
## sock.sendPacket(packet, "192.168.1.1")
## ```

import std/[strutils, times]

# Platform-specific imports
when defined(windows):
  import std/winlean
  import std/os

  # Windows socket constants and types
  const
    INVALID_SOCKET* = SocketHandle(-1)
    SOCKET_ERROR* = -1
    SOL_SOCKET* = 0xFFFF
    SO_BROADCAST* = 0x0020
    SO_RCVTIMEO* = 0x1006
    SO_SNDTIMEO* = 0x1005
    IPPROTO_IP* = 0
    IP_HDRINCL* = 2
    SIO_RCVALL* = 0x98000001'u32  # Enable promiscuous mode
    RCVALL_ON* = 1
    RCVALL_OFF* = 0

  type
    RawSocket* = object
      handle: SocketHandle
      family: cint
      protocol: cint
      isOpen*: bool

else:
  import std/posix

  const
    # SocketHandle is a distinct type on POSIX, so we need to cast -1 to SocketHandle
    INVALID_SOCKET* = SocketHandle(-1)
    SOCKET_ERROR* = -1
    IP_HDRINCL* = 3

  type
    RawSocket* = object
      handle: SocketHandle  # Changed from cint to SocketHandle to match posix.socket return type
      family: cint
      protocol: cint
      isOpen*: bool

# Protocol constants (cross-platform)
# Note: Main IPPROTO_* constants are defined in nimpacket.nim
# These are for internal raw socket use only
const
  AF_INET* = 2
  AF_INET6* = 23  # Windows value
  SOCK_RAW* = 3
  IPPROTO_RAW* = 255

# Internal protocol constants (not exported to avoid conflict with nimpacket)
const
  IPPROTO_ICMP = 1
  IPPROTO_TCP = 6
  IPPROTO_UDP = 17
  IPPROTO_ICMPV6 = 58

# Error types
type
  RawSocketError* = object of CatchableError
  PrivilegeError* = object of RawSocketError
  SocketCreateError* = object of RawSocketError
  SocketSendError* = object of RawSocketError
  SocketReceiveError* = object of RawSocketError
  SocketOptionError* = object of RawSocketError

when defined(windows):
  # Windows-specific socket functions
  proc WSAStartup(wVersionRequired: uint16, lpWSAData: pointer): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "WSAStartup".}

  proc WSACleanup(): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "WSACleanup".}

  proc WSAGetLastError(): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "WSAGetLastError".}

  proc socket(af, typ, protocol: cint): SocketHandle
    {.stdcall, dynlib: "ws2_32.dll", importc: "socket".}

  proc closesocket(s: SocketHandle): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "closesocket".}

  proc setsockopt(s: SocketHandle, level, optname: cint, optval: pointer, optlen: cint): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "setsockopt".}

  proc sendto(s: SocketHandle, buf: pointer, len: cint, flags: cint,
              to: pointer, tolen: cint): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "sendto".}

  proc recvfrom(s: SocketHandle, buf: pointer, len: cint, flags: cint,
                fromaddr: pointer, fromlen: ptr cint): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "recvfrom".}

  proc ioctlsocket(s: SocketHandle, cmd: uint32, argp: ptr culong): cint
    {.stdcall, dynlib: "ws2_32.dll", importc: "ioctlsocket".}

  proc inet_addr(cp: cstring): uint32
    {.stdcall, dynlib: "ws2_32.dll", importc: "inet_addr".}

  # Simple admin check using Windows API
  proc IsUserAnAdmin(): WINBOOL
    {.stdcall, dynlib: "shell32.dll", importc: "IsUserAnAdmin".}

  proc ShellExecuteW(hwnd: pointer, lpOperation: WideCString, lpFile: WideCString,
                     lpParameters: WideCString, lpDirectory: WideCString,
                     nShowCmd: cint): pointer
    {.stdcall, dynlib: "shell32.dll", importc: "ShellExecuteW".}

  proc isRunningAsAdmin*(): bool =
    return IsUserAnAdmin() != 0

  # Initialize Winsock
  var wsaInitialized {.global.} = false

  proc initWinsock() =
    if not wsaInitialized:
      var wsaData: array[400, byte]  # WSADATA structure
      let result = WSAStartup(0x0202, addr wsaData[0])  # Request Winsock 2.2
      if result != 0:
        raise newException(SocketCreateError, "Failed to initialize Winsock: " & $result)
      wsaInitialized = true

else:
  proc isRunningAsAdmin*(): bool =
    return posix.geteuid() == 0

proc elevateIfNeeded*() =
  when defined(windows):
    if not isRunningAsAdmin():
      let exePath = getAppFilename()
      # Build command line arguments to pass to elevated process
      var params = ""
      for i in 1..paramCount():
        if i > 1:
          params &= " "
        params &= "\"" & paramStr(i) & "\""

      let result = ShellExecuteW(nil, newWideCString("runas"),
                                 newWideCString(exePath),
                                 newWideCString(params), nil, 1)
      if cast[int](result) > 32:
        quit(0)
      else:
        echo "Failed to elevate. Please run as Administrator manually."
        quit(1)

proc createRawSocket*(family: cint = AF_INET, protocol: cint = IPPROTO_TCP): RawSocket =
  if not isRunningAsAdmin():
    raise newException(PrivilegeError,
      "Raw socket creation requires administrator/root privileges. " &
      "On Windows, run as Administrator. On Unix, run as root or with CAP_NET_RAW.")

  when defined(windows):
    initWinsock()

    let handle = socket(family, SOCK_RAW, protocol)
    if handle == INVALID_SOCKET:
      let error = WSAGetLastError()
      raise newException(SocketCreateError,
        "Failed to create raw socket. Error code: " & $error)
  else:
    let handle = posix.socket(family, SOCK_RAW, protocol)
    if handle == INVALID_SOCKET:
      raise newException(SocketCreateError,
        "Failed to create raw socket. Error: " & $posix.errno)

  result = RawSocket(
    handle: handle,
    family: family,
    protocol: protocol,
    isOpen: true
  )

proc close*(sock: var RawSocket) =
  if sock.isOpen:
    when defined(windows):
      discard closesocket(sock.handle)
    else:
      # Cast SocketHandle to cint since posix.close expects cint
      discard posix.close(sock.handle.cint)
    sock.isOpen = false

proc setIPHeaderInclude*(sock: RawSocket, enable: bool) =
  if not sock.isOpen:
    raise newException(SocketOptionError, "Socket is not open")

  var optval: cint = if enable: 1 else: 0

  when defined(windows):
    let result = setsockopt(sock.handle, IPPROTO_IP, IP_HDRINCL,
                           addr optval, sizeof(optval).cint)
    if result == SOCKET_ERROR:
      let error = WSAGetLastError()
      raise newException(SocketOptionError,
        "Failed to set IP_HDRINCL option. Error code: " & $error)
  else:
    let result = posix.setsockopt(sock.handle, posix.IPPROTO_IP, IP_HDRINCL,
                                 addr optval, sizeof(optval).SockLen)
    if result == SOCKET_ERROR:
      raise newException(SocketOptionError,
        "Failed to set IP_HDRINCL option. Error: " & $posix.errno)

proc setBroadcast*(sock: RawSocket, enable: bool) =
  if not sock.isOpen:
    raise newException(SocketOptionError, "Socket is not open")

  var optval: cint = if enable: 1 else: 0

  when defined(windows):
    let result = setsockopt(sock.handle, SOL_SOCKET, SO_BROADCAST,
                           addr optval, sizeof(optval).cint)
    if result == SOCKET_ERROR:
      let error = WSAGetLastError()
      raise newException(SocketOptionError,
        "Failed to set SO_BROADCAST option. Error code: " & $error)
  else:
    let result = posix.setsockopt(sock.handle, posix.SOL_SOCKET,
                                 posix.SO_BROADCAST,
                                 addr optval, sizeof(optval).SockLen)
    if result == SOCKET_ERROR:
      raise newException(SocketOptionError,
        "Failed to set SO_BROADCAST option. Error: " & $posix.errno)

proc setReceiveTimeout*(sock: RawSocket, timeoutMs: int) =
  if not sock.isOpen:
    raise newException(SocketOptionError, "Socket is not open")

  when defined(windows):
    var timeout: cint = timeoutMs.cint
    let result = setsockopt(sock.handle, SOL_SOCKET, SO_RCVTIMEO,
                           addr timeout, sizeof(timeout).cint)
    if result == SOCKET_ERROR:
      let error = WSAGetLastError()
      raise newException(SocketOptionError,
        "Failed to set receive timeout. Error code: " & $error)
  else:
    var timeout: Timeval
    timeout.tv_sec = posix.Time(timeoutMs div 1000)
    timeout.tv_usec = posix.Suseconds((timeoutMs mod 1000) * 1000)
    let result = posix.setsockopt(sock.handle, posix.SOL_SOCKET,
                                 posix.SO_RCVTIMEO,
                                 addr timeout, sizeof(timeout).SockLen)
    if result == SOCKET_ERROR:
      raise newException(SocketOptionError,
        "Failed to set receive timeout. Error: " & $posix.errno)

proc setPromiscuousMode*(sock: RawSocket, enable: bool) =
  if not sock.isOpen:
    raise newException(SocketOptionError, "Socket is not open")

  when defined(windows):
    var optval: culong = if enable: RCVALL_ON else: RCVALL_OFF
    var bytesReturned: culong = 0
    let result = ioctlsocket(sock.handle, SIO_RCVALL, addr optval)
    if result == SOCKET_ERROR:
      let error = WSAGetLastError()
      raise newException(SocketOptionError,
        "Failed to set promiscuous mode. Error code: " & $error)
  else:
    raise newException(SocketOptionError,
      "Promiscuous mode requires libpcap on this platform")

proc sendPacket*(sock: RawSocket, packet: seq[byte], destIP: string): int {.discardable.} =
  if not sock.isOpen:
    raise newException(SocketSendError, "Socket is not open")

  if packet.len == 0:
    raise newException(SocketSendError, "Cannot send empty packet")

  when defined(windows):
    var destAddr: array[16, byte]
    zeroMem(addr destAddr[0], 16)

    destAddr[0] = (sock.family and 0xFF).byte
    destAddr[1] = ((sock.family shr 8) and 0xFF).byte
    destAddr[2] = 0
    destAddr[3] = 0

    let ipAddr = inet_addr(cstring(destIP))
    copyMem(addr destAddr[4], unsafeAddr ipAddr, 4)

    let bytesSent = sendto(sock.handle, unsafeAddr packet[0], packet.len.cint,
                           0, addr destAddr[0], 16)

    if bytesSent == SOCKET_ERROR:
      let error = WSAGetLastError()
      raise newException(SocketSendError,
        "Failed to send packet. Error code: " & $error)

    return bytesSent
  else:
    var destAddr: Sockaddr_in
    destAddr.sin_family = sock.family.uint16
    destAddr.sin_port = 0

    if posix.inet_pton(posix.AF_INET, cstring(destIP),
                      addr destAddr.sin_addr) != 1:
      raise newException(SocketSendError, "Invalid IP address: " & destIP)

    let bytesSent = posix.sendto(sock.handle.cint, unsafeAddr packet[0],
                                packet.len, 0.cint,
                                cast[ptr SockAddr](addr destAddr),
                                sizeof(destAddr).Socklen)

    if bytesSent == SOCKET_ERROR:
      raise newException(SocketSendError,
        "Failed to send packet. Error: " & $posix.errno)

    return bytesSent.int

proc receivePacket*(sock: RawSocket, maxSize: int = 65535,
                   timeoutMs: int = 5000): seq[byte] =
  if not sock.isOpen:
    raise newException(SocketReceiveError, "Socket is not open")

  try:
    sock.setReceiveTimeout(timeoutMs)
  except:
    discard

  var buffer = newSeq[byte](maxSize)

  when defined(windows):
    var fromAddr: array[16, byte]
    var fromLen: cint = 16

    let bytesReceived = recvfrom(sock.handle, addr buffer[0], maxSize.cint,
                                 0, addr fromAddr[0], addr fromLen)

    if bytesReceived == SOCKET_ERROR:
      let error = WSAGetLastError()
      if error == 10060:  # WSAETIMEDOUT
        return @[]
      raise newException(SocketReceiveError,
        "Failed to receive packet. Error code: " & $error)

    if bytesReceived == 0:
      return @[]

    result = buffer[0..<bytesReceived]
  else:
    var fromAddr: Sockaddr_in
    var fromLen: SockLen = sizeof(fromAddr).SockLen

    let bytesReceived = posix.recvfrom(sock.handle, addr buffer[0],
                                      maxSize.csize_t, 0,
                                      cast[ptr SockAddr](addr fromAddr),
                                      addr fromLen)

    if bytesReceived == SOCKET_ERROR:
      if posix.errno == EAGAIN or posix.errno == EWOULDBLOCK:
        return @[]
      raise newException(SocketReceiveError,
        "Failed to receive packet. Error: " & $posix.errno)

    if bytesReceived == 0:
      return @[]

    result = buffer[0..<bytesReceived]

proc receivePacketWithTimeout*(sock: RawSocket, timeoutSec: float,
                               filter: proc(data: seq[byte]): bool = nil): seq[byte] =
  let startTime = epochTime()
  let endTime = startTime + timeoutSec

  while epochTime() < endTime:
    let remainingMs = ((endTime - epochTime()) * 1000).int
    if remainingMs <= 0:
      break

    try:
      let packet = sock.receivePacket(timeoutMs = min(remainingMs, 1000))
      if packet.len > 0:
        if filter == nil or filter(packet):
          return packet
    except SocketReceiveError:
      discard

  return @[]

proc createICMPSocket*(family: cint = AF_INET): RawSocket =
  if family == AF_INET:
    return createRawSocket(AF_INET, IPPROTO_ICMP)
  else:
    return createRawSocket(AF_INET6, IPPROTO_ICMPV6)

proc createTCPSocket*(): RawSocket =
  # On Windows, use IPPROTO_RAW for TCP to avoid restrictions
  when defined(windows):
    return createRawSocket(AF_INET, IPPROTO_RAW)
  else:
    return createRawSocket(AF_INET, IPPROTO_TCP)

proc createUDPSocket*(): RawSocket =
  # On Windows, use IPPROTO_RAW for UDP to avoid restrictions
  when defined(windows):
    return createRawSocket(AF_INET, IPPROTO_RAW)
  else:
    return createRawSocket(AF_INET, IPPROTO_UDP)

proc createIPSocket*(): RawSocket =
  return createRawSocket(AF_INET, IPPROTO_RAW)
