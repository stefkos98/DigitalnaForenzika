#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */

#include "ArpMonitor.h"

ArpMonitor::ArpMonitor()
{
  iFoundedPackets = 0;
}

void ArpMonitor::run(Sniffer& sniffer) {
  iFoundedPackets = 0;
  sniffer.sniff_loop(
    bind(
      &ArpMonitor::callback,
      this,
      std::placeholders::_1
    )
  );
}

void ArpMonitor::run(FileSniffer& sniffer) {
  iFoundedPackets = 0;
  sniffer.sniff_loop(
    bind(
      &ArpMonitor::callback,
      this,
      std::placeholders::_1
    )
  );
}

bool ArpMonitor::callback(const PDU& pdu) {
  // Retrieve the ARP layer
  const ARP& arp = pdu.rfind_pdu<ARP>();
  // Is it an ARP reply?
  if (arp.opcode() == ARP::REPLY) {
    iFoundedPackets++;
    // Let's check if there's already an entry for this address
    auto iter = addresses.find(arp.sender_ip_addr());
    if (iter == addresses.end()) {
      // We haven't seen this address. Save it.
      addresses.insert({ arp.sender_ip_addr(), arp.sender_hw_addr() });
      cout << GREEN << "[INFO] " << arp.sender_ip_addr() 
        << " is at " << arp.sender_hw_addr() << RESET << std::endl;
    }
    else {
      // We've seen this address. If it's not the same HW address, inform it
      if (arp.sender_hw_addr() != iter->second) {
        cout << RED << "[WARNING] " << arp.sender_ip_addr() 
          << " is at "<< iter->second << " but also at " << arp.sender_hw_addr()<< RESET << endl;
      }
    }
  }
  return true;
}

int ArpMonitor::getNumberOfPackets()
{
  return iFoundedPackets;
}