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

static constexpr int MAX_REQUESTS = 8;
static constexpr int BUF_SIZE     = 512;
static constexpr int HEADER_SIZE  = 12;

namespace DnsFlag {
  // Flags in HOST byte order (after ntohs conversion)
  // DNS flags layout: [ra][z][ad][cd][rcode4][rcode3][rcode2][rcode1]
  // [rd][tc][aa][opcode4][opcode3][opcode2][opcode1][qr]
  static constexpr uint16_t QR     = 0x8000;  // bit 15
  static constexpr uint16_t OPCODE = 0x7800;  // bits 11-14 (4 bits)
  static constexpr uint16_t AA     = 0x0400;  // bit 10
  static constexpr uint16_t TC     = 0x0200;  // bit 9
  static constexpr uint16_t RD     = 0x0100;  // bit 8
  static constexpr uint16_t RA     = 0x0080;  // bit 7
  static constexpr uint16_t Z      = 0x0040;  // bit 6 (reserved)
  static constexpr uint16_t AD     = 0x0020;  // bit 5 (DNSSEC Authentic Data)
  static constexpr uint16_t CD    = 0x0010;  // bit 4 (DNSSEC Checking Disabled)
  static constexpr uint16_t RCODE = 0x000F;  // bits 0-3 (4 bits)

  static constexpr int OPCODE_SHIFT = 11;  // Shift right 11 bits to get opcode
  static constexpr int RCODE_SHIFT  = 0;   // No shift needed for RCODE
}  // namespace DnsFlag

namespace QTYPE {
  static constexpr uint16_t A     = 1;    // IPv4 address
  static constexpr uint16_t NS    = 2;    // Name server
  static constexpr uint16_t CNAME = 5;    // Canonical Name
  static constexpr uint16_t SOA   = 6;    // Start of a zone of authority
  static constexpr uint16_t PTR   = 12;   // Domain name pointer
  static constexpr uint16_t MX    = 15;   // Mail exchange
  static constexpr uint16_t TXT   = 16;   // Text record
  static constexpr uint16_t AAAA  = 28;   // IPv6 address
  static constexpr uint16_t ANY   = 255;  // All record types
}  // namespace QTYPE

namespace QCLASS {
  static constexpr uint16_t IN  = 1;    // Internet (most common)
  static constexpr uint16_t CS  = 2;    // CSNET (obsolete)
  static constexpr uint16_t CH  = 3;    // CHAOS protocol
  static constexpr uint16_t HS  = 4;    // Hesiod protocol
  static constexpr uint16_t ANY = 255;  // All classes
}  // namespace QCLASS

namespace RCODE {
  static constexpr unsigned short NO_ERROR              = 0;
  static constexpr unsigned short FORMAT_ERROR          = 1;
  static constexpr unsigned short SERVER_ERROR          = 2;
  static constexpr unsigned short NAME_ERROR            = 3;
  static constexpr unsigned short NOT_IMPLEMENTED_ERROR = 4;
  static constexpr unsigned short REFUSED_ERROR         = 5;
}  // namespace RCODE

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
inline bool dnsAD(uint16_t flags) {
  return (flags & DnsFlag::AD) != 0;
}
inline bool dnsCD(uint16_t flags) {
  return (flags & DnsFlag::CD) != 0;
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
struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};
#pragma pack(pop)

struct DnsRecord {
  std::string name;
  std::string type;
  std::string rec_class;
  uint32_t    ttl;
  std::string rdata;
};

struct DnsAnswer {
  std::string encoded_name;
  uint16_t    type;
  uint16_t    rec_class;
  uint32_t    ttl;
  uint16_t    rdlength;
  char*       rdata;
};

void printDnsHeader(const DnsHeader& header) {
  // Directly use header fields and extraction functions
  bool    qr     = dnsIsRequest(header.flags);
  uint8_t opcode = dnsOpcode(header.flags);
  bool    aa     = dnsAA(header.flags);
  bool    tc     = dnsTC(header.flags);
  bool    rd     = dnsRD(header.flags);
  bool    ra     = dnsRA(header.flags);
  bool    z      = dnsZBitsValid(header.flags);
  bool    ad     = dnsAD(header.flags);
  bool    cd     = dnsCD(header.flags);
  uint8_t rcode  = dnsRcode(header.flags);

  std::cout << "  ID: " << header.id << "\n";
  std::cout << "  QR: " << (qr ? "Query" : "Response") << "\n";
  std::cout << "  Opcode: " << static_cast<int>(opcode) << "\n";
  std::cout << "  AA: " << (aa ? "Authoritative" : "Non-authoritative") << "\n";
  std::cout << "  TC: " << (tc ? "Truncated" : "Not truncated") << "\n";
  std::cout << "  RD: " << (rd ? "Recursion desired" : "No recursion desired")
            << "\n";
  std::cout << "  RA: "
            << (ra ? "Recursion available" : "No recursion available") << "\n";
  std::cout << "  Z: " << (z ? "Valid" : "Invalid (should be 0)") << "\n";
  std::cout << "  AD: " << (ad ? "Authentic Data" : "No authentic data")
            << "\n";
  std::cout << "  CD: " << (cd ? "Checking Disabled" : "Checking enabled")
            << "\n";
  std::cout << "  RCODE: " << static_cast<int>(rcode) << "\n";
  std::cout << "  Questions: " << header.qdcount << "\n";
  std::cout << "  Answers: " << header.ancount << "\n";
  std::cout << "  Authority: " << header.nscount << "\n";
  std::cout << "  Additional: " << header.arcount << "\n\n";
}

struct DnsQuestion {
  std::string qname;
  uint16_t    qtype;
  uint16_t    qclass;
};

std::vector<DnsRecord> ReadConfig(const std::string& cfg_path) {
  try {
    YAML::Node config = YAML::LoadFile(cfg_path);

    std::vector<DnsRecord> records;

    for (const auto& item : config["records"]) {
      DnsRecord rec;

      rec.name      = item["name"].as<std::string>();
      rec.type      = item["type"].as<std::string>();
      rec.rec_class = item["class"].as<std::string>();
      rec.ttl       = item["ttl"].as<int>();
      rec.rdata     = item["data"].as<std::string>();

      records.push_back(rec);
    }

    return records;
  } catch (const YAML::Exception& e) {
    std::cerr << "Error parsing config file: " << e.what() << std::endl;
    return {};
  }
}

void convertHeaderToHost(DnsHeader& header) {
  header.id      = ntohs(header.id);
  header.flags   = ntohs(header.flags);
  header.qdcount = ntohs(header.qdcount);
  header.nscount = ntohs(header.nscount);
  header.ancount = ntohs(header.ancount);
  header.arcount = ntohs(header.arcount);
}

void convertHeaderToNetwork(DnsHeader& header) {
  header.id      = htons(header.id);
  header.flags   = htons(header.flags);
  header.qdcount = htons(header.qdcount);
  header.nscount = htons(header.nscount);
  header.ancount = htons(header.ancount);
  header.arcount = htons(header.arcount);
}

std::string encodeDomainName(const std::string& domain) {
  std::string encoded;
  size_t      start   = 0;
  size_t      dot_pos = domain.find('.');

  while (dot_pos != std::string::npos) {
    std::string label = domain.substr(start, dot_pos - start);
    encoded += static_cast<char>(label.length());
    encoded += label;
    start   = dot_pos + 1;
    dot_pos = domain.find('.', start);
  }

  if (start < domain.length()) {
    std::string label = domain.substr(start);
    encoded += static_cast<char>(label.length());
    encoded += label;
  }

  encoded += '\0';

  return encoded;
}

void convertRdataToNetworkFormat(DnsAnswer&         answer,
                                 const std::string& rdata_str) {
  switch (answer.type) {
  case QTYPE::A: {
    answer.rdlength = 4;
    answer.rdata    = new char[answer.rdlength];

    struct in_addr addr;
    if (inet_pton(AF_INET, rdata_str.c_str(), &addr) == 1) {
      memcpy(answer.rdata, &addr.s_addr, answer.rdlength);
    } else {
      memset(answer.rdata, 0, answer.rdlength);
    }
    break;
  }

  case QTYPE::AAAA: {
    answer.rdlength = 16;
    answer.rdata    = new char[answer.rdlength];

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, rdata_str.c_str(), &addr6) == 1) {
      memcpy(answer.rdata, &addr6.s6_addr, answer.rdlength);
    } else {
      memset(answer.rdata, 0, answer.rdlength);
    }
    break;
  }

  case QTYPE::CNAME: {
    std::string encoded_domain = encodeDomainName(rdata_str);
    answer.rdlength            = encoded_domain.length();
    answer.rdata               = new char[answer.rdlength];
    memcpy(answer.rdata, encoded_domain.c_str(), answer.rdlength);
    break;
  }

  case QTYPE::TXT: {
    answer.rdlength = rdata_str.length() + 1;
    answer.rdata    = new char[answer.rdlength];
    answer.rdata[0] = static_cast<char>(rdata_str.length());
    memcpy(answer.rdata + 1, rdata_str.c_str(), rdata_str.length());
    break;
  }

  case QTYPE::NS: {
    std::string encoded_domain = encodeDomainName(rdata_str);
    answer.rdlength            = encoded_domain.length();
    answer.rdata               = new char[answer.rdlength];
    memcpy(answer.rdata, encoded_domain.c_str(), answer.rdlength);
    break;
  }

  case QTYPE::MX: {
    size_t space_pos = rdata_str.find(' ');
    if (space_pos != std::string::npos) {
      uint16_t priority =
          static_cast<uint16_t>(std::stoi(rdata_str.substr(0, space_pos)));
      std::string domain = rdata_str.substr(space_pos + 1);

      std::string encoded_domain = encodeDomainName(domain);
      answer.rdlength            = 2 + encoded_domain.length();
      answer.rdata               = new char[answer.rdlength];

      uint16_t priority_net = htons(priority);
      memcpy(answer.rdata, &priority_net, 2);
      memcpy(answer.rdata + 2, encoded_domain.c_str(), encoded_domain.length());
    } else {
      // Invalid MX format, treat as domain only with priority 0
      std::string encoded_domain = encodeDomainName(rdata_str);
      answer.rdlength            = 2 + encoded_domain.length();
      answer.rdata               = new char[answer.rdlength];

      uint16_t priority_net = htons(0);
      memcpy(answer.rdata, &priority_net, 2);
      memcpy(answer.rdata + 2, encoded_domain.c_str(), encoded_domain.length());
    }
    break;
  }

  case QTYPE::PTR: {
    std::string encoded_domain = encodeDomainName(rdata_str);
    answer.rdlength            = encoded_domain.length();
    answer.rdata               = new char[answer.rdlength];
    memcpy(answer.rdata, encoded_domain.c_str(), answer.rdlength);
    break;
  }

  default: {
    // For other record types, treat as raw data
    answer.rdlength = rdata_str.length();
    answer.rdata    = new char[answer.rdlength];
    memcpy(answer.rdata, rdata_str.c_str(), answer.rdlength);
    break;
  }
  }
}

void cleanupDnsAnswer(DnsAnswer& answer) {
  if (answer.rdata != nullptr) {
    delete[] answer.rdata;
    answer.rdata = nullptr;
  }
}

void sendError(int sock_fd, unsigned short rcode, const DnsHeader& req_header,
               const char* question_start, const char* question_end,
               struct sockaddr* client_addr, socklen_t addr_len) {
  DnsHeader resp_header = req_header;
  dnsSetQR(resp_header.flags, true);
  dnsSetAA(resp_header.flags, true);
  dnsSetRcode(resp_header.flags, rcode);

  resp_header.qdcount = 1;
  resp_header.ancount = 0;
  resp_header.arcount = 0;
  resp_header.nscount = 0;

  // std::cout << "SENDING HEADER:" << std::endl;
  // printDnsHeader(resp_header);

  // Convert to network byte order
  convertHeaderToNetwork(resp_header);

  // Create response buffer with header + original question
  char response_buffer[BUF_SIZE];
  memcpy(response_buffer, &resp_header, sizeof(resp_header));

  // Copy the original question section
  size_t question_len = question_end - question_start;
  memcpy(response_buffer + sizeof(resp_header), question_start, question_len);

  size_t total_len = sizeof(resp_header) + question_len;
  sendto(sock_fd, response_buffer, total_len, MSG_CONFIRM, client_addr,
         addr_len);
}

void sendAnswers(int sock_fd, const DnsHeader& req_header,
                 const char* question_start, const char* question_end,
                 const std::vector<DnsAnswer>& answers,
                 struct sockaddr* client_addr, socklen_t addr_len) {
  DnsHeader resp_header = req_header;
  dnsSetQR(resp_header.flags, true);
  dnsSetAA(resp_header.flags, true);
  dnsSetRA(resp_header.flags, true);
  dnsSetRcode(resp_header.flags, RCODE::NO_ERROR);

  resp_header.qdcount = 1;
  resp_header.ancount = static_cast<uint16_t>(answers.size());
  resp_header.arcount = 0;
  resp_header.nscount = 0;

  // std::cout << "SENDING HEADER:" << std::endl;
  // printDnsHeader(resp_header);

  // Convert to network byte order
  convertHeaderToNetwork(resp_header);

  // Create response buffer
  char  response_buffer[BUF_SIZE];
  char* writer_pos = response_buffer;
  memcpy(writer_pos, &resp_header, sizeof(resp_header));
  writer_pos += sizeof(resp_header);

  // Copy the original question section
  size_t question_len = question_end - question_start;
  memcpy(writer_pos, question_start, question_len);
  writer_pos += question_len;

  // Add answer records
  for (const auto& answer : answers) {
    memcpy(writer_pos, answer.encoded_name.c_str(),
           answer.encoded_name.length());
    writer_pos += answer.encoded_name.length();

    uint16_t type = htons(answer.type);
    memcpy(writer_pos, &type, 2);
    writer_pos += sizeof(type);

    uint16_t rec_class = htons(answer.rec_class);
    memcpy(writer_pos, &rec_class, 2);
    writer_pos += sizeof(rec_class);

    uint32_t ttl = htonl(answer.ttl);
    memcpy(writer_pos, &ttl, 4);
    writer_pos += sizeof(ttl);

    uint16_t rdlength = htons(answer.rdlength);
    memcpy(writer_pos, &rdlength, sizeof(rdlength));
    writer_pos += sizeof(rdlength);

    memcpy(writer_pos, answer.rdata, answer.rdlength);
    writer_pos += answer.rdlength;
  }
  sendto(sock_fd, response_buffer, writer_pos - response_buffer, MSG_CONFIRM,
         client_addr, addr_len);
}

int main(int argc, char** argv) {
  std::string cfg_path = "./config.yaml";
  uint16_t    port     = 53;

  if (argc >= 2) {
    if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
      std::cout << "Usage: " << argv[0] << " [config_file] [port]" << std::endl;
      std::cout
          << "  config_file: Path to YAML config file (default: ./config.yaml)"
          << std::endl;
      std::cout << "  port: Port number to listen on (default: 53)"
                << std::endl;
      std::cout << "Examples:" << std::endl;
      std::cout << "  " << argv[0]
                << "                    # Use default config and port 53"
                << std::endl;
      std::cout << "  " << argv[0]
                << " config.yaml 5353   # Use custom config and port 5353"
                << std::endl;
      return 0;
    }
    cfg_path = argv[1];
  }
  if (argc >= 3) {
    try {
      int port_int = std::stoi(argv[2]);
      if (port_int < 1 || port_int > 65535) {
        throw std::out_of_range("Port out of range");
      }
      port = static_cast<uint16_t>(port_int);
    } catch (const std::exception& e) {
      std::cerr << "Error: Invalid port number '" << argv[2]
                << "'. Using default port 53." << std::endl;
      port = 53;
    }
  }

  std::cout << "Starting DNS server on port " << port
            << " with config: " << cfg_path << std::endl;

  auto records = ReadConfig(cfg_path);

  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

  sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(port);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  int error_code =
      bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (error_code == -1) {
    perror("Error binding address to the socket: ");
    exit(EXIT_FAILURE);
  }

  sockaddr_in client_addr;
  char        buffer[BUF_SIZE];

  socklen_t addrlen = sizeof(client_addr);

  while (true) {
    int read = recvfrom(sock_fd, buffer, BUF_SIZE, MSG_WAITALL,
                        (struct sockaddr*)&client_addr, &addrlen);

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

    DnsHeader req_header;
    memcpy(&req_header, reader_pos, sizeof(req_header));
    reader_pos += sizeof(req_header);

    char* question_begin = reader_pos;
    char* question_end   = nullptr;

    convertHeaderToHost(req_header);

    printDnsHeader(req_header);

    if (!dnsIsRequest(req_header.flags)) {
      std::cout << "Recieved DNS response. Ignoring..." << std::endl;
      continue;
    }

    switch (dnsOpcode(req_header.flags)) {
    case 0:
      break;
    case 1:
      break;
    case 2:
      break;
    default:
      std::cout << "Unsupported OPCODE. Ignoring..." << std::endl;
      continue;
    }

    unsigned short rcode = 0;

    for (uint16_t i = 0; i < req_header.qdcount && rcode == 0; ++i) {
      std::cout << "Question number " << i + 1 << ":" << std::endl;

      DnsQuestion question;
      std::string encoded_name;
      while (true) {
        uint8_t len = *reader_pos;
        encoded_name += static_cast<char>(len);
        ++reader_pos;

        if (len == 0) {
          break;
        }

        std::string token(reader_pos, reader_pos + len);

        encoded_name += token;
        reader_pos += len;

        if (!question.qname.empty()) {
          question.qname += ".";
        }
        question.qname += token;
      }

      std::cout << "QNAME  = " << question.qname << std::endl;

      question.qtype = ntohs(*reinterpret_cast<uint16_t*>(reader_pos));
      reader_pos += sizeof(question.qtype);

      std::string qtype_name;
      switch (question.qtype) {
      case QTYPE::A:
        qtype_name = "A";
        break;
      case QTYPE::NS:
        qtype_name = "NS";
        break;
      case QTYPE::CNAME:
        qtype_name = "CNAME";
        break;
      case QTYPE::SOA:
        qtype_name = "SOA";
        break;
      case QTYPE::PTR:
        qtype_name = "PTR";
        break;
      case QTYPE::MX:
        qtype_name = "MX";
        break;
      case QTYPE::TXT:
        qtype_name = "TXT";
        break;
      case QTYPE::AAAA:
        qtype_name = "AAAA";
        break;
      case QTYPE::ANY:
        qtype_name = "ANY";
        break;
      default:
        qtype_name = "UNKNOWN";
        std::cerr << "ERR: UNKNOWN QTYPE" << std::endl;
        rcode = RCODE::FORMAT_ERROR;
        continue;
      }

      std::cout << "QTYPE  = " << qtype_name << " (" << question.qtype << ")"
                << std::endl;

      question.qclass = ntohs(*reinterpret_cast<uint16_t*>(reader_pos));
      reader_pos += sizeof(question.qclass);
      question_end = reader_pos;

      std::string qclass_name;
      switch (question.qclass) {
      case QCLASS::IN:
        qclass_name = "IN";
        break;
      case QCLASS::CS:
        qclass_name = "CS";
        break;
      case QCLASS::CH:
        qclass_name = "CH";
        break;
      case QCLASS::HS:
        qclass_name = "HS";
        break;
      case QCLASS::ANY:
        qclass_name = "ANY";
        break;
      default:
        qclass_name = "UNKNOWN";
        std::cerr << "ERR: UNKNOWN QCLASS" << std::endl;
        rcode = RCODE::FORMAT_ERROR;
        continue;
      }

      std::cout << "QCLASS = " << qclass_name << " (" << question.qclass << ")"
                << std::endl;

      std::vector<DnsAnswer> answers;

      for (const auto& rec : records) {
        if (rec.name == question.qname && rec.type == qtype_name &&
            rec.rec_class == qclass_name) {
          DnsAnswer answer;
          answer.encoded_name = encoded_name;
          answer.type         = question.qtype;
          answer.rec_class    = question.qclass;
          answer.ttl          = rec.ttl;
          answer.rdlength     = 0;
          answer.rdata        = nullptr;

          convertRdataToNetworkFormat(answer, rec.rdata);
          answers.push_back(answer);
        }
      }

      if (answers.empty()) {
        std::cerr << "ERR: DOMAIN NAME NOT FOUND" << std::endl;
        rcode = RCODE::NAME_ERROR;
      }

      if (rcode != 0) {
        sendError(sock_fd, rcode, req_header, question_begin, question_end,
                  (struct sockaddr*)&client_addr, addrlen);
        continue;
      }

      sendAnswers(sock_fd, req_header, question_begin, question_end, answers,
                  (struct sockaddr*)&client_addr, addrlen);

      for (auto& answer : answers) {
        cleanupDnsAnswer(answer);
      }
    }
  }

  close(sock_fd);

  return 0;
}