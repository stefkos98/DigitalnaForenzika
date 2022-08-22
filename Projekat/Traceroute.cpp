#define NOMINMAX
#include "Traceroute.h"

Traceroute::Traceroute(NetworkInterface interface, IPv4Address address) 
  : iface(interface), addr(address), lowest_dest_ttl(numeric_limits<int>::max()) {
  sequence = random_device()() & 0xffff;
}

result_type Traceroute::trace() {
  SnifferConfiguration config;
  config.set_promisc_mode(false);
  // ICMPs that aren't sent from us.
  config.set_filter(
    "ip proto \\icmp and not src host " + iface.info().ip_addr.to_string());
  Sniffer sniffer(iface.name(), config);

  PacketSender sender;
  // Create our handler
  auto handler = bind(
    &Traceroute::sniff_callback,
    this,
    std::placeholders::_1
  );
  // We're running
  running = true;
  // Start the sniff thread
  thread sniff_thread(
    [&]() {
      sniffer.sniff_loop(handler);
    }
  );
  send_packets(sender);
  sniff_thread.join();
  // If the final hop responded, add its address at the appropriate ttl
  if (lowest_dest_ttl != numeric_limits<int>::max()) {
    results[lowest_dest_ttl] = addr;
  }
  // Clear our results and return what we've found
  return move(results);
}
void Traceroute::send_packets(PacketSender& sender) {
  // ICMPs are icmp-requests by default
  IP ip = IP(addr, iface.addresses().ip_addr) / ICMP();
  ICMP& icmp = ip.rfind_pdu<ICMP>();
  icmp.sequence(sequence);
  // We'll find at most 20 hops.

  for (auto i = 1; i <= 20; ++i) {
    // Set this ICMP id
    icmp.id(i);
    // Set the time-to-live option
    ip.ttl(i);

    // Critical section
    {
      lock_guard<mutex> _(lock);
      ttls[i] = i;
    }

    sender.send(ip);
    // Give it a little time
    sleep_for(milliseconds(100));
  }
  running = false;
  sender.send(ip);
}

bool Traceroute::sniff_callback(PDU& pdu) {
  // Find IP and ICMP PDUs
  const IP& ip = pdu.rfind_pdu<IP>();
  const ICMP& icmp = pdu.rfind_pdu<ICMP>();
  // Check if this is an ICMP TTL exceeded error response
  if (icmp.type() == ICMP::TIME_EXCEEDED) {
    // Fetch the IP PDU attached to the ICMP response
    const IP inner_ip = pdu.rfind_pdu<RawPDU>().to<IP>();
    // Now get the ICMP layer
    const ICMP& inner_icmp = inner_ip.rfind_pdu<ICMP>();
    // Make sure this is one of our packets.
    if (inner_icmp.sequence() == sequence) {
      ttl_map::const_iterator iter;

      // Critical section
      {
        std::lock_guard<std::mutex> _(lock);
        iter = ttls.find(inner_icmp.id());
      }

      // It's an actual response
      if (iter != ttls.end()) {
        // Store it
        results[inner_icmp.id()] = ip.src_addr();
      }
    }
  }
  // Otherwise, this could be the final hop making an echo response
  else if (icmp.type() == ICMP::ECHO_REPLY && icmp.sequence() == sequence &&
    ip.src_addr() == addr) { 
    // Keep the lowest ttl seen for the destination.
    lowest_dest_ttl = min(lowest_dest_ttl, static_cast<int>(icmp.id()));
  }
  return running;
}