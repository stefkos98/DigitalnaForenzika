#define TINS_STATIC
#include <iostream>
#include <string>
#include <stdexcept>
#include "tins/ip.h"
#include "tins/ip_reassembler.h"
#include "tins/sniffer.h"
#include "tins/packet_writer.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::exception;

using Tins::IPv4Reassembler;
using Tins::IP;
using Tins::Packet;
using Tins::FileSniffer;
using Tins::PacketWriter;
using Tins::DataLinkType;

// This example reads packets from a pcap file and writes them to a new file.
// If any IPv4 fragmented packets are found in the input file, then they will
// be reassembled before writing them, so instead of the individual fragments
// it will write the whole packet.

class Defragmenter {
public:

  Defragmenter(const string& input_file, const string& output_file);
  void run();
  uint64_t total_packets_reassembled() const;
  uint64_t total_packets_fragmented() const;
private:
    FileSniffer sniffer_;
    IPv4Reassembler reassembler_;
    PacketWriter writer_;
    uint64_t total_reassembled_;
    uint64_t total_fragmented_;

};
