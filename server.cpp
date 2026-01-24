#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using namespace std;

// -------------------------------------------
//  Constantlar
// -------------------------------------------


const int MSS = 100;
const int HEADER_SIZE = 40;
const int UDP_HEADER_SIZE = 8;
const int MAX_BUFFER_SIZE = 65536;
const int RECV_BUFFER_SIZE = 2000; //normalde daha küçük olmalı ama clark test hızlı bitsin diye arttırıldı
const int SEND_BUFFER_SIZE = 8000;
const char *const SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 8080;
const int PACKET_TIMEOUT_MS = 1000;
const int MAX_RETRIES = 5;
const unsigned char PKT_TYPE_DATA = 0x01;
const unsigned char PKT_TYPE_ACK = 0x02;
const unsigned char PKT_TYPE_FIN = 0x03;



// -------------------------------------------
//  Packet structure
//  Header + Payload
// -------------------------------------------


#pragma pack(push, 1)
struct Packet {
  unsigned char type;
  unsigned int seq_num;
  unsigned int ack_num;
  unsigned short win_size;
  unsigned short data_len;
  char data[MSS];

  Packet() : type(0), seq_num(0), ack_num(0), win_size(0), data_len(0) {
    memset(data, 0, MSS);
  }
  static Packet createData(unsigned int seq, const char *payload,
                           unsigned short len) {
    Packet pkt;
    pkt.type = PKT_TYPE_DATA;
    pkt.seq_num = seq;
    pkt.data_len = (len > MSS) ? MSS : len;
    memcpy(pkt.data, payload, pkt.data_len);
    return pkt;
  }
  static Packet createAck(unsigned int ack, unsigned short window) {
    Packet pkt;
    pkt.type = PKT_TYPE_ACK;
    pkt.ack_num = ack;
    pkt.win_size = window;
    return pkt;
  }
  static Packet createFin(unsigned int seq) {
    Packet pkt;
    pkt.type = PKT_TYPE_FIN;
    pkt.seq_num = seq;
    return pkt;
  }
};
#pragma pack(pop)

// -------------------------------------------
//  Simülasyon verileri
// -------------------------------------------

class SimulationStats {
public:
  long total_payload_sent = 0;
  long total_packets_sent = 0;
  long total_ack_packets = 0;


  void reset() {
    total_payload_sent = 0;
    total_packets_sent = 0;
    total_ack_packets = 0;
  }

  void print_report(const string &scenario_name, long fileSize) {
    long total_overhead =
        (total_packets_sent + total_ack_packets) * HEADER_SIZE;
    long total_traffic = total_payload_sent + total_overhead;
    double efficiency = (total_traffic > 0)
                            ? ((double)total_payload_sent / total_traffic) * 100
                            : 0;

    cout << "\n-------------------------------------------" << endl;
    cout << "   FINAL ANALYSE: " << scenario_name << endl;
    cout << "-------------------------------------------" << endl;
    cout << "File size:                " << fileSize << " bytes" << endl;
    cout << "1. Transferred Data:     " << total_payload_sent << " bytes"
         << endl;
    cout << "2. Total Data Package:       " << total_packets_sent << endl;
    cout << "3. Total ACK Package:        " << total_ack_packets << endl;
    cout << "4. Total Header Cost:   " << total_overhead << " bytes"
         << endl;
    cout << "5. Total Network Traffic: " << total_traffic << " bytes"
         << endl;
    cout << "---------------------------------------------" << endl;
    cout << fixed << setprecision(2);
    cout << "Efficiency Score: %" << efficiency << endl;
    cout << "-------------------------------------------\n" << endl;
  }
};




// -------------------------------------------
//  UDP SERVER - Receiver with Clark Algorithm
//  Portu dinler ve veriyi alir
// -------------------------------------------


class UDPServer {
private:
  SOCKET sock;
  sockaddr_in serverAddr, clientAddr;
  int clientAddrLen;

  char *recvBuffer;
  int maxBufferSize;
  int currentBufferUsage;

  bool useClark;
  SimulationStats *stats;

  ofstream outFile;
  long totalBytesReceived;

public:
  UDPServer(bool clarkEnabled, SimulationStats *statsPtr)
      : useClark(clarkEnabled), stats(statsPtr), totalBytesReceived(0) {
    recvBuffer = new char[RECV_BUFFER_SIZE];
    maxBufferSize = RECV_BUFFER_SIZE;
    currentBufferUsage = 0;
    clientAddrLen = sizeof(clientAddr);
  }

  ~UDPServer() {
    delete[] recvBuffer;
    if (outFile.is_open())
      outFile.close();
    closesocket(sock);
  }
//1.UDP soketi
  bool initialize() {
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
      cerr << "Socket creation failed: " << WSAGetLastError() << endl;
      return false;
    }

    int timeout = PACKET_TIMEOUT_MS * 10;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout));

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_PORT);
//2. soket yerel porta bağlandı
    if (bind(sock, (sockaddr *)&serverAddr, sizeof(serverAddr)) ==
        SOCKET_ERROR) {
      cerr << "Bind failed: " << WSAGetLastError() << endl;
      return false;
    }

    outFile.open("received_output.bin", ios::binary);
    if (!outFile) {
      cerr << "Output file creation failed!" << endl;
      return false;
    }


    cout << "Server listening on port " << SERVER_PORT << "..." << endl;
    cout << "Clark Algorithm: " << (useClark ? "ON" : "OFF") << endl;
    return true;
  }
  //Paketleri bekler işler ve yanıtlar
  void run() {
    Packet packet;
    bool running = true;
    int timeoutCount = 0;
    const int MAX_TIMEOUTS = 30; // 30 saniye
    cout << "Waiting for connection..." << endl;

    while (running) {
      int bytesReceived = recvfrom(sock, (char *)&packet, sizeof(Packet), 0,
                                   (sockaddr *)&clientAddr, &clientAddrLen);

      if (bytesReceived == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT) {
          timeoutCount++;
          if (timeoutCount >= MAX_TIMEOUTS) {
            cout << "Timeout." << endl;
            break;
          }
          continue; // Beklemeye devam et
        }
        cerr << "Receive error: " << err << endl;
        break;
      }
      //paket alındığında sayaç 0a döner
      timeoutCount = 0;

      if (packet.type == PKT_TYPE_DATA) {
        handleDataPacket(packet);
      } else if (packet.type == PKT_TYPE_FIN) {
        cout << "\nTransfer completed!" << endl;
        sendAck(packet.seq_num + 1);
        running = false;
      }
    }

    stats->print_report(useClark ? "Clark Enabled" : "Clark Disabled",totalBytesReceived);
  }
  // Gelen veri paketini isler ve dosyaya yazar
private:
  void handleDataPacket(const Packet &packet) {
    currentBufferUsage += packet.data_len;//buffer dolulugunu arttırır
    outFile.write(packet.data, packet.data_len);
    totalBytesReceived += packet.data_len;
    stats->total_packets_sent++;
    stats->total_payload_sent += packet.data_len;
    sendAck(packet.seq_num + packet.data_len);
    simulateSlowConsumer();
  }
  // ACK Onay paketi gonderir ve Pencere Boyutunu bildirir
  void sendAck(unsigned int ackNum) {
    int availableWindow = maxBufferSize - currentBufferUsage;

    // Clark algoritması
    if (useClark && availableWindow < MSS) {
      availableWindow = 0;
      cout << "[CLARK] Window too small, advertising 0" << endl;
    }

    Packet ack =
        Packet::createAck(ackNum, (unsigned short)min(availableWindow, 65535));
    sendto(sock, (char *)&ack, sizeof(Packet), 0, (sockaddr *)&clientAddr,
           clientAddrLen);
    stats->total_ack_packets++;
  }
  // Tuketim hizini simule eder bufferdan veri okuma
  void simulateSlowConsumer() {
    if (currentBufferUsage > 0) {
      currentBufferUsage = max(0, currentBufferUsage - 75);
    }
  }
};


//  Main Func

int main(int argc, char *argv[]) {
  bool useClark = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--clark") == 0 && i + 1 < argc) {
      useClark = (strcmp(argv[i + 1], "1") == 0);
    }
  }

  cout << "-------------------------------------------" << endl;
  cout << "   UDP SERVER - Clark Algorithm Demo" << endl;
  cout << "-------------------------------------------" << endl;
  cout << "DEBUG: sizeof(Packet) = " << sizeof(Packet) << " bytes" << endl;
  cout << "DEBUG: MSS = " << MSS << " bytes" << endl;
  cout << "-------------------------------------------";
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << "WSAStartup failed!" << endl;
    return 1;
  }
  SimulationStats stats;
  UDPServer server(useClark, &stats);

  if (!server.initialize()) {
    WSACleanup();
    return 1;
  }
  server.run();
  WSACleanup();
  return 0;

}