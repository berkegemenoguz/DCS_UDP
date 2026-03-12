# DCS_UDP — Nagle & Clark Algorithm Demonstration over UDP

A C++ client-server application that demonstrates the **Nagle Algorithm** (sender-side) and the **Clark Algorithm** (receiver-side) for solving the **Silly Window Syndrome (SWS)** problem over UDP sockets on Windows.

## Overview

In TCP/IP networking, sending many tiny packets wastes bandwidth due to fixed header overhead. Two classic solutions address this from opposite ends:

| Algorithm | Side | Strategy |
|-----------|------|----------|
| **Nagle** | Sender | Buffers small writes and coalesces them into MSS-sized packets before sending |
| **Clark** | Receiver | Advertises a zero window until enough buffer space (≥ MSS) is available |

This project implements both algorithms over UDP with a custom reliable-transfer protocol (sequence numbers, ACKs, FIN handshake) so you can observe and compare network efficiency with the algorithms **enabled vs. disabled**.

## Project Structure

```
DCS_UDP/
├── client.cpp          # UDP client with Nagle algorithm implementation
├── server.cpp          # UDP server with Clark algorithm implementation
├── CMakeLists.txt      # CMake build configuration
├── LICENSE             # MIT License
└── README.md
```

## How It Works

### Client (`client.cpp`)
- Reads a binary file and splits it into small 30-byte application-level chunks.
- **Nagle ON**: Accumulates chunks in a buffer until an MSS-sized (100 bytes) packet can be sent, reducing the total number of packets.
- **Nagle OFF**: Sends each small chunk as a separate packet immediately, demonstrating the SWS problem with high header overhead.
- Implements stop-and-wait reliability with ACK-based flow control.

### Server (`server.cpp`)
- Listens on a UDP port, receives data packets, writes payload to an output file.
- **Clark ON**: If the available receive-buffer space falls below MSS, it advertises a **zero window** to the client, preventing the sender from transmitting tiny bursts into a nearly-full buffer.
- **Clark OFF**: Always advertises the actual remaining window, even if very small.
- Simulates a slow consumer that gradually drains the buffer, creating realistic back-pressure.

## Requirements

- **OS**: Windows (uses Winsock2 API)
- **Compiler**: MSVC or any C++17 compatible compiler on Windows
- **Build System**: CMake ≥ 3.10

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

This produces two executables: `server.exe` and `client.exe`.

## Usage

### 1. Start the Server

```bash
# Clark algorithm OFF (default)
./server

# Clark algorithm ON
./server --clark 1
```

### 2. Run the Client (in a separate terminal)

```bash
# Nagle algorithm OFF (default) — sends many small packets
./client --file input_test.bin

# Nagle algorithm ON — coalesces small writes into larger packets
./client --nagle 1 --file input_test.bin
```

> **Note:** If the specified input file does not exist, the client automatically generates a 50 KB test file.

### Command-Line Flags

| Flag | Binary | Values | Description |
|------|--------|--------|-------------|
| `--nagle` | client | `0` (default) / `1` | Enable or disable the Nagle algorithm |
| `--clark` | server | `0` (default) / `1` | Enable or disable the Clark algorithm |
| `--file` | client | file path | Path to the input file to transfer |

## Example Output

After a transfer completes, both client and server print an efficiency report:

```
=============================================
   FINAL ANALYSE: Nagle Enabled (Optimized)
=============================================
File Size:                50000 bytes
1. Transfered data:     50000 bytes
2. Total DATA Package:       500
3. Total ACK Package:        500
4. Total Header Cost:   140000 bytes
5. Total Network Traffic: 190000 bytes
---------------------------------------------
Efficiency Score: %26.32
=============================================
```

## Key Parameters

| Constant | Value | Purpose |
|----------|-------|---------|
| `MSS` | 100 bytes | Maximum Segment Size per packet |
| `HEADER_SIZE` | 140 bytes (client) / 40 bytes (server) | Protocol header overhead |
| `RECV_BUFFER_SIZE` | 2000 bytes | Server receive buffer capacity |
| `SEND_BUFFER_SIZE` | 8000 bytes | Client send window |
| `SMALL_CHUNK` | 30 bytes | Simulated application write size |

## License

This project is licensed under the [MIT License](LICENSE).

**© 2026 Berk Egemen Oğuz**