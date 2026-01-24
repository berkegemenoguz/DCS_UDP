#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

// =============================================
//  CONSTANTS
// =============================================

const int MSS = 100; // Küçük MSS - Nagle/Clark etkisini görmek için
const int HEADER_SIZE = 140;
const int UDP_HEADER_SIZE = 8;
const int MAX_BUFFER_SIZE = 65536;
const int RECV_BUFFER_SIZE = 500;
const int SEND_BUFFER_SIZE = 8000;
const char *const SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 8080;
const int PACKET_TIMEOUT_MS = 1000;
const int MAX_RETRIES = 5;
const unsigned char PKT_TYPE_DATA = 0x01;
const unsigned char PKT_TYPE_ACK = 0x02;
const unsigned char PKT_TYPE_FIN = 0x03;

// =============================================
//  PACKET STRUCTURE
//  Protokol baslik (header) ve veri yapisi
// =============================================

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

// =============================================
//  SIMULATION STATS
//  Performans olcum sinifi
// =============================================

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

    cout << "\n=============================================" << endl;
    cout << "   FINAL ANALYSE: " << scenario_name << endl;
    cout << "=============================================" << endl;
    cout << "File Size:                " << fileSize << " bytes" << endl;
    cout << "1. Transfered data:     " << total_payload_sent << " bytes"
         << endl;
    cout << "2. Total DATA Package:       " << total_packets_sent << endl;
    cout << "3. Total ACK Package:        " << total_ack_packets << endl;
    cout << "4. Total Header Cost:   " << total_overhead << " bytes"
         << endl;
    cout << "5. Total Network Traffic: " << total_traffic << " bytes"
         << endl;
    cout << "---------------------------------------------" << endl;
    cout << fixed << setprecision(2);
    cout << "Efficiency Score: %" << efficiency << endl;
    cout << "=============================================\n" << endl;
  }
};

// =============================================
//  UDP CLIENT - Sender with Nagle Algorithm
//  Istemci sinifi: Dosyayi okur, parcalara boler
//  ve Nagle algoritmasina gore sunucuya gonderir.
// =============================================

class UDPClient {
private:
  SOCKET sock;
  sockaddr_in serverAddr;
  int serverAddrLen;

  vector<char> sendBuffer;
  char *nagleBuffer;
  int nagleBufferSize;

  unsigned int nextSeqNum;
  int currentWindow;
  bool dataInFlight;

  bool useNagle;
  SimulationStats *stats;
  long originalFileSize;

  // Kurucu Metot: Degiskenleri baslatir ve buffer ayirir
public:
  UDPClient(bool nagleEnabled, SimulationStats *statsPtr)
      : useNagle(nagleEnabled), stats(statsPtr), originalFileSize(0) {
    nagleBuffer = new char[MSS];
    nagleBufferSize = 0;
    nextSeqNum = 1;
    currentWindow = SEND_BUFFER_SIZE;
    dataInFlight = false;
    serverAddrLen = sizeof(serverAddr);
  }

  ~UDPClient() {
    delete[] nagleBuffer;
    closesocket(sock);
  }
  // Soket olusturma ve sunucu adresini ayarlama

  bool initialize() {
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    // 1. UDP Soketini ac
    if (sock == INVALID_SOCKET) {
      cerr << "Socket creation failed: " << WSAGetLastError() << endl;
      return false;
    }

    int timeout = PACKET_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(SERVER_PORT);

    cout << "Client connecting to " << SERVER_IP << ":" << SERVER_PORT << endl;
    cout << "Nagle Algorithm: " << (useNagle ? "ON" : "OFF") << endl;
    return true;
  }

  bool loadFile(const string &path) {
    ifstream file(path, ios::binary);
    if (!file) {
      cerr << "File not found: " << path << endl;
      return false;
    }

    sendBuffer.assign((istreambuf_iterator<char>(file)),
                      istreambuf_iterator<char>());
    originalFileSize = sendBuffer.size();
    cout << "File loaded: " << originalFileSize << " bytes" << endl;
    return true;
  }
  // Ana Gonderim Dongusu
  // Nagle algoritmasi kullaniliyorsa paketleri birlestirir,
  // kullanilmiyorsa direkt gonderir.
  void run() {
    cout << "\nTransfer starting up..." << endl;
    cout << "Nagle: "
         << (useNagle ? "ON - Packages will be collected"
                      : "OFF - Each item will be shipped separately.")
         << endl;

    const int SMALL_CHUNK = 30; // Uygulamanin yazdigi kucuk parcalar

    while (!sendBuffer.empty()) {
      // CLARK RESPONSE: pencere 0 ise bekle
      // CLARK RESPONSE: pencere 0 ise probe gonder
      // Eger sunucu yerim yok derse (Window=0) deadlocku onlemek icin
      // periyodik olarak probe atiyoruz.
      static int clarkCount = 0;
      while (currentWindow <= 0) {
        if (clarkCount % 100 == 0) {
          cout << "[CLARK] Window 0, Probe being sent... (" << clarkCount << ")"
               << endl;
        }
        clarkCount++;

        // Zero Window Probe: Server'i tetiklemek icin bos paket gonder
        Packet probe = Packet::createData(nextSeqNum, nullptr, 0);
        sendto(sock, (char *)&probe, sizeof(Packet), 0, (sockaddr *)&serverAddr,serverAddrLen);

        waitForAck();
        if (currentWindow > 0)
          Sleep(50); // Hala 0 ise biraz bekle
      }

      int chunkSize = min((int)sendBuffer.size(), SMALL_CHUNK);

      if (useNagle) {
        // NAGLE ALGORITMASI (ON)
        // Kucuk veri parcalarini buffer'da biriktir.
        // MSS dolunca veya veri bitince gonder.

        // NAGLE ON: Kucuk parcalari biriktir, MSS dolunca gonder

        // Buffer tasacak mi? Once gonder
        if (nagleBufferSize + chunkSize > MSS) {
          if (nagleBufferSize > 0) {
            Packet pkt = Packet::createData(nextSeqNum, nagleBuffer,
                                            (unsigned short)nagleBufferSize);
            sendto(sock, (char *)&pkt, sizeof(Packet), 0,
                   (sockaddr *)&serverAddr, serverAddrLen);

            stats->total_packets_sent++;
            stats->total_payload_sent += nagleBufferSize;
            cout << "[NAGLE] Bulk shipping: " << nagleBufferSize
                 << " bytes, Packages #" << stats->total_packets_sent << endl;

            nextSeqNum += nagleBufferSize;
            nagleBufferSize = 0;
            waitForAck();
          }
        }

        // Simdi chunk'i buffer'a ekle
        memcpy(nagleBuffer + nagleBufferSize, sendBuffer.data(), chunkSize);
        nagleBufferSize += chunkSize;
        sendBuffer.erase(sendBuffer.begin(), sendBuffer.begin() + chunkSize);

        // Son veri mi? Kalan ne varsa gonder
        if (sendBuffer.empty() && nagleBufferSize > 0) {
          Packet pkt = Packet::createData(nextSeqNum, nagleBuffer,(unsigned short)nagleBufferSize);
          sendto(sock, (char *)&pkt, sizeof(Packet), 0, (sockaddr *)&serverAddr,serverAddrLen);

          stats->total_packets_sent++;
          stats->total_payload_sent += nagleBufferSize;
          cout << "[NAGLE] Last package: " << nagleBufferSize << " bytes, Packages #"
               << stats->total_packets_sent << endl;

          nextSeqNum += nagleBufferSize;
          nagleBufferSize = 0;
          waitForAck();
        }
      } else {
        // NAGLE OFF: Her kucuk parcayi ayri paket olarak gonder
        Packet pkt = Packet::createData(nextSeqNum, sendBuffer.data(),
                                        (unsigned short)chunkSize);
        sendto(sock, (char *)&pkt, sizeof(Packet), 0, (sockaddr *)&serverAddr,
               serverAddrLen);

        sendBuffer.erase(sendBuffer.begin(), sendBuffer.begin() + chunkSize);
        stats->total_packets_sent++;
        stats->total_payload_sent += chunkSize;

        cout << "Sent: " << chunkSize << " bytes, Package #"
             << stats->total_packets_sent << endl;

        nextSeqNum += chunkSize;
        waitForAck();
      }
    }

    sendFinPacket();
    string mode =
        useNagle ? "Nagle Enabled (Optimized)" : "Nagle Disabled (SWS Problem)";
    stats->print_report(mode, originalFileSize);
  }
  // Veri paketi olusturup gonderir
private:
  void sendDataPacket(int size) {
    Packet pkt =
        Packet::createData(nextSeqNum, sendBuffer.data(), (unsigned short)size);
    sendto(sock, (char *)&pkt, sizeof(Packet), 0, (sockaddr *)&serverAddr,
           serverAddrLen);

    sendBuffer.erase(sendBuffer.begin(), sendBuffer.begin() + size);
    currentWindow -= size;
    dataInFlight = true;

    stats->total_packets_sent++;
    stats->total_payload_sent += size;

    cout << "Sent: SEQ=" << nextSeqNum << ", SIZE=" << size
         << ", Remaining=" << sendBuffer.size() << endl;

    nextSeqNum += size;
  }
  // Nagle Buffer'indaki veriyi paketleyip gonderir
  void sendNagleBuffer() {
    if (nagleBufferSize == 0)
      return;

    Packet pkt = Packet::createData(nextSeqNum, nagleBuffer,
                                    (unsigned short)nagleBufferSize);
    sendto(sock, (char *)&pkt, sizeof(Packet), 0, (sockaddr *)&serverAddr,
           serverAddrLen);

    stats->total_packets_sent++;
    stats->total_payload_sent += nagleBufferSize;

    cout << "[NAGLE] Sent accumulated: SEQ=" << nextSeqNum
         << ", SIZE=" << nagleBufferSize << endl;

    nextSeqNum += nagleBufferSize;
    nagleBufferSize = 0;
    dataInFlight = true;
  }
  // Transferin bittigini bildiren fin paketi gonderir
  void sendFinPacket() {
    Packet fin = Packet::createFin(nextSeqNum);
    sendto(sock, (char *)&fin, sizeof(Packet), 0, (sockaddr *)&serverAddr,
           serverAddrLen);
    cout << "\nFIN sent, waiting for final ACK..." << endl;
    waitForAck();
  }
  // Sunucudan ACK (Onay) bekler
  // Timeout olursa paketi tekrar gonderir
  void waitForAck() {
    Packet ack;
    int bytesReceived = recvfrom(sock, (char *)&ack, sizeof(Packet), 0,
                                 (sockaddr *)&serverAddr, &serverAddrLen);

    if (bytesReceived > 0 && ack.type == PKT_TYPE_ACK) {
      currentWindow = ack.win_size;
      dataInFlight = false;
      stats->total_ack_packets++;

      if (currentWindow == 0) {
        cout << "[FLOW CONTROL] Window=0, waiting..." << endl;
        Sleep(100);
      }
    }
  }
};

// =============================================
//  MAIN FUNCTION
// =============================================

int main(int argc, char *argv[]) {
  bool useNagle = false;
  string inputFile = "input_test.bin";

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--nagle") == 0 && i + 1 < argc) {
      useNagle = (strcmp(argv[i + 1], "1") == 0);
    }
    if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
      inputFile = argv[i + 1];
    }
  }

  cout << "=============================================" << endl;
  cout << "   UDP CLIENT - Nagle Algorithm Demo" << endl;
  cout << "=============================================" << endl;
  cout << "DEBUG: sizeof(Packet) = " << sizeof(Packet) << " bytes" << endl;
  cout << "DEBUG: MSS = " << MSS << " bytes" << endl;

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    cerr << "WSAStartup failed!" << endl;
    return 1;
  }

  {
    ifstream test(inputFile, ios::binary);
    if (!test) {
      cout << "Creating test file..." << endl;
      ofstream dummy(inputFile, ios::binary);
      for (int i = 0; i < 50000; ++i)
        dummy << "A";
      dummy.close();
    }
  }

  SimulationStats stats;
  UDPClient client(useNagle, &stats);

  if (!client.initialize()) {
    WSACleanup();
    return 1;
  }

  if (!client.loadFile(inputFile)) {
    WSACleanup();
    return 1;
  }

  client.run();
  WSACleanup();
  return 0;

}