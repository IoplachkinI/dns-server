#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <unordered_map>

static constexpr int MAX_REQUESTS = 8;
static constexpr int BUF_SIZE     = 1024;
static constexpr int HEADER_SIZE  = 12;  // in bytes

namespace DnsFlag {
  static constexpr uint16_t QR     = 0x8000;
  static constexpr uint16_t OPCODE = 0x7800;  // 4 bits
  static constexpr uint16_t AA     = 0x0400;
  static constexpr uint16_t TC     = 0x0200;
  static constexpr uint16_t RD     = 0x0100;
  static constexpr uint16_t RA     = 0x0080;
  static constexpr uint16_t Z      = 0x0070;  // must be zero
  static constexpr uint16_t RCODE  = 0x000F;  // 4 bits

  static constexpr int OPCODE_SHIFT = 11;
  static constexpr int RCODE_SHIFT  = 0;
}  // namespace DnsFlag

inline bool dnsIsRequest(uint16_t flags) {
  return (flags & DnsFlag::QR) == 0;
}
inline bool dnsAA(uint16_t flags) {
  return (flags & DnsFlag::AA) != 0;
}
inline bool dnsTC(uint16_t flags) {
  return (flags & DnsFlag::TC) != 0;
}
inline bool dnsRD(uint16_t flags) {
  return (flags & DnsFlag::RD) != 0;
}
inline bool dnsRA(uint16_t flags) {
  return (flags & DnsFlag::RA) != 0;
}

inline uint8_t dnsOpcode(uint16_t flags) {
  return static_cast<uint8_t>((flags & DnsFlag::OPCODE) >>
                              DnsFlag::OPCODE_SHIFT);
}

inline uint8_t dnsRcode(uint16_t flags) {
  return static_cast<uint8_t>((flags & DnsFlag::RCODE) >> DnsFlag::RCODE_SHIFT);
}

inline bool dnsZBitsValid(uint16_t flags) {
  return (flags & DnsFlag::Z) == 0;
}

// Setters (modify host-order flags)
inline void dnsSetQR(uint16_t& flags, bool v) {
  if (v) {
    flags |= DnsFlag::QR;
  } else {
    flags &= ~DnsFlag::QR;
  }
}
inline void dnsSetAA(uint16_t& flags, bool v) {
  if (v) {
    flags |= DnsFlag::AA;
  } else {
    flags &= ~DnsFlag::AA;
  }
}
inline void dnsSetTC(uint16_t& flags, bool v) {
  if (v) {
    flags |= DnsFlag::TC;
  } else {
    flags &= ~DnsFlag::TC;
  }
}
inline void dnsSetRD(uint16_t& flags, bool v) {
  if (v) {
    flags |= DnsFlag::RD;
  } else {
    flags &= ~DnsFlag::RD;
  }
}
inline void dnsSetRA(uint16_t& flags, bool v) {
  if (v) {
    flags |= DnsFlag::RA;
  } else {
    flags &= ~DnsFlag::RA;
  }
}

inline void dnsSetOpcode(uint16_t& flags, uint8_t opcode) {
  flags = static_cast<uint16_t>(
      (flags & ~DnsFlag::OPCODE) |
      ((static_cast<uint16_t>(opcode & 0x0F) << DnsFlag::OPCODE_SHIFT)));
}

inline void dnsSetRcode(uint16_t& flags, uint8_t rcode) {
  flags = static_cast<uint16_t>(
      (flags & ~DnsFlag::RCODE) |
      (static_cast<uint16_t>(rcode & 0x0F) << DnsFlag::RCODE_SHIFT));
}

#pragma pack(push, 1)
// DnsHeader stores the DNS header fields in network format (Big Endian)
struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t additional_count;
};
#pragma pack(pop)

struct DnsQuestion {
  std::string qname;
  uint16_t    qtype;
  uint16_t    qclass;
};

struct DNSMap {
  std::unordered_map<std::string, std::string> UrlToAddr;
  std::unordered_map<std::string, std::string> AddrToUrl;
};

std::optional<DNSMap> ReadConfig(const std::string& cfg_path) {
  try {
    YAML::Node config = YAML::LoadFile(cfg_path);
    DNSMap     dns_map;

    for (const auto& item : config["entries"]) {
      std::string url  = item["url"].as<std::string>();
      std::string addr = item["addr"].as<std::string>();

      dns_map.UrlToAddr[url]  = addr;
      dns_map.AddrToUrl[addr] = url;
    }

    return dns_map;
  } catch (const YAML::Exception& e) {
    std::cerr << "Error parsing config file: " << e.what() << std::endl;
    return {};
  }
}

int main(int argc, char** argv) {
  // Config

  std::string cfg_path = "./config.yaml";

  if (argc == 2) {
    cfg_path = argv[1];
  }

  auto read_cfg_result = ReadConfig(cfg_path);
  if (!read_cfg_result.has_value()) {
    exit(EXIT_FAILURE);
  }

  DNSMap dns_map = read_cfg_result.value();

  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(53);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  int error_code =
      bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (error_code == -1) {
    perror("Error binding address to the socket: ");
    exit(EXIT_FAILURE);
  }

  sockaddr_in client_addr;
  char        buffer[BUF_SIZE];

  socklen_t len = sizeof(client_addr);

  while (true) {
    int read = recvfrom(sock_fd, buffer, BUF_SIZE, MSG_WAITALL,
                        (struct sockaddr*)&client_addr, &len);

    char* reader_pos = buffer;

    if (read == -1) {
      perror("Error reading from client: ");
      exit(EXIT_FAILURE);
    }

    std::cout << "Message recieved: " << buffer << std::endl;

    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip)) != nullptr) {
      uint16_t port = ntohs(client_addr.sin_port);
      std::cout << "From: " << ip << ":" << port << std::endl;
    }

    DnsHeader header;
    memcpy(&header, reader_pos, sizeof(header));
    reader_pos += sizeof(header);

    uint16_t req_id = ntohs(header.id);
    uint16_t flags  = ntohs(header.flags);

    if (!dnsIsRequest(flags)) {
      std::cout << "Recieved DNS response. Ignoring..." << std::endl;
    }

    if (!dnsZBitsValid(flags)) {
      std::cout << "Zero bits invalid. Ignoring..." << std::endl;
    }

    switch (dnsOpcode(flags)) {
    case 0:
      break;
    case 1:
      break;
    case 2:
      break;
    default:
      std::cout << "Unsupported OPCODE. Ignoring..." << std::endl;
    }

    for (uint16_t i = 0; i < header.question_count; ++i) {
      std::cout << "Parsing question number " << i + 1 << ":" << std::endl;

      DnsQuestion question;
      while (true) {
        uint16_t len = ntohs(*reinterpret_cast<uint16_t*>(reader_pos));
        reader_pos += sizeof(uint16_t);

        if (len == 0) {
          break;
        }

        std::string token(reader_pos, reader_pos + len);
        reader_pos += len;

        if (!question.qname.empty()) {
          question.qname += ".";
        }
        question.qname += token;
      }

      std::cout << "QNAME = " << question.qname << std::endl;
      ;

      question.qclass = ntohs(*reinterpret_cast<uint16_t*>(reader_pos));
      reader_pos += sizeof(question.qclass);

      std::cout << "QCLASS = " << question.qclass << std::endl;

      question.qtype = ntohs(*reinterpret_cast<uint16_t*>(reader_pos));
      reader_pos += sizeof(question.qtype);

      std::cout << "QTYPE = " << question.qclass << std::endl;
    }

    // const char *hello_msg = "Hello from server!";

    // sendto(sock_fd, hello_msg, strlen(hello_msg), MSG_CONFIRM,
    //        (struct sockaddr *)&client_addr, len);
  }

  close(sock_fd);

  return 0;
}