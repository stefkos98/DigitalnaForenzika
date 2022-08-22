#include "Defragmenter.h"
Defragmenter::Defragmenter(const string& input_file, const string& output_file)
  : sniffer_(input_file),
  writer_(output_file, (PacketWriter::LinkType)sniffer_.link_type()),
  total_reassembled_(0), total_fragmented_(0) {
}

void Defragmenter::run() {
  Packet packet;
  // Read packets and keep going until there's no more packets to read
  while (packet = sniffer_.next_packet()) {
    // Try to reassemble the packet
    IPv4Reassembler::PacketStatus status = reassembler_.process(*packet.pdu());

    // If we did reassemble it, increase this counter
    if (status == IPv4Reassembler::REASSEMBLED) {
      total_reassembled_++;
      total_fragmented_++;
    }

    // Regardless, we'll write it into the output file unless it's fragmented
    // (and not yet reassembled) 
    if (status != IPv4Reassembler::FRAGMENTED) {
      writer_.write(packet);
    }
    else
    {
      total_fragmented_++;
    }
  }
}

uint64_t Defragmenter::total_packets_reassembled() const {
  return total_reassembled_;
}

uint64_t Defragmenter::total_packets_fragmented() const {
  return total_fragmented_;
}