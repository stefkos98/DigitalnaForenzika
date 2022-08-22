// Projekat.cpp : This file contains the 'main' function. Program execution begins and ends there.
// {0D634653-9EBC-4CE4-8E8E-710A04F2E9C2} ethernet
// {CEFB2FC3-E47E-4FA3-BBF3-7ACD4D19970E} wifi
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */
#define TINS_STATIC
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>

using namespace Tins;
#include <iostream>
using namespace std;
bool doo(PDU& some_pdu) {
  // Search for it. If there is no IP PDU in the packet, 
  // the loop goes on
  const IP& ip = some_pdu.rfind_pdu<IP>(); // non-const works as well
  std::cout << "Destination address: " << ip.dst_addr() << std::endl;
  // Just one packet please
  return false;
}
bool handler(const PDU& pkt) {
  static int count = 0;
  // Lookup the UDP PDU
  const UDP& udp = pkt.rfind_pdu<UDP>();
  // We need source/destination port to be 53
  if (udp.sport() == 53 || udp.dport() == 53) {
    // Interpret it as DNS. This might throw, but Sniffer catches it
    DNS dns = pkt.rfind_pdu<RawPDU>().to<DNS>();
    // Just print out each query's domain name
    for (const auto& query : dns.queries()) {
      std::cout << query.dname() << std::endl;
    }
    if (++count == 10)
    return false;
  }
  return true;
}
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

// This will be called when there's new client data
void on_client_dataP(Stream& stream) {
  // Get the client's payload, this is a vector<uint8_t>
  const Stream::payload_type& payload = stream.client_payload();

  // Now do something with it!
}

// This will be called when there's new server data
void on_server_dataP(Stream& stream) {
  // Process the server's data
}
void on_closed_stream(Stream& stream) {
  // Process the closed stream
}
// New stream is seen
void on_new_stream(Stream& stream) {
  // Configure the client and server data callbacks
  stream.client_data_callback(&on_client_dataP);
  stream.server_data_callback(&on_server_dataP);
  stream.stream_closed_callback(&on_closed_stream);
  // If we want to buffer received packets
   // Disables auto-deleting the client's data after the callback is executed
  stream.auto_cleanup_client_data(true);

  // Same thing for the server's data
  stream.auto_cleanup_server_data(true);

  // Or a shortcut to doing this for both:
  stream.auto_cleanup_payloads(true);

  // We don't even want to buffer the client's data
  stream.ignore_client_data();
}

// A stream was terminated. The second argument is the reason why it was terminated
void on_stream_terminated(Stream& stream, StreamFollower::TerminationReason reason) {

}

#pragma comment(lib, "ws2_32.lib")
int main012() {
  // Create our follower
  Tins::TCPIP::StreamFollower follower;

  // Set the callback for new streams. Note that this is a std::function, so you
  // could use std::bind and use a member function for this
  follower.new_stream_callback(&on_new_stream);

  // Now set up the termination callback. This will be called whenever a stream is 
  // stopped being followed for some of the reasons explained above
  follower.stream_termination_callback(&on_stream_terminated);

  // Now create some sniffer
    // Sniffing with config
  SnifferConfiguration config;
  config.set_promisc_mode(true);

  NetworkInterface iface = NetworkInterface::default_interface();
  Sniffer sniffer(iface.name());

  // And start sniffing, forwarding all packets to our follower
  sniffer.sniff_loop([&](PDU& pdu) {
    follower.process_packet(pdu);
    return true;
    });
  IP ipdata;
 // ipdata.add_option();
  //ipdata.search_option();
  return 0;
}
int main123() {
  //WINSOCK
  WORD wVersionRequested;
  WSADATA wsaData;
  wVersionRequested = MAKEWORD(2, 2);   
  int err = WSAStartup(wVersionRequested, &wsaData);
  EthernetII eth;
  IP* ip = new IP();
  TCP* tcp = new TCP();

  // tcp is ip's inner pdu
  ip->inner_pdu(tcp);

  // ip is eth's inner pdu
  eth.inner_pdu(ip);

  EthernetII eth2 = EthernetII() / IP() / TCP();
  TCP* tcpPointer = eth2.find_pdu<TCP>();
  if (tcpPointer != nullptr)
  {
    cout << "There is TCP Pointer" << endl;
  }
  if (eth2.find_pdu<IP>())
  {
    IP& ipPointer = eth2.rfind_pdu<IP>();  // pdu not found exception if there is no reference
    cout << "There is IP datagram" << endl;
  }
  std::string low_string("127.0.0.1");
  IPv4Address lo("127.0.0.1");
  IPv4Address empty; // represents the address 0.0.0.0

  // IPv6
  IPv6Address lo_6("::1");

  // Write it to stdout
  std::cout << "Lo: " << lo << std::endl;
  std::cout << "Empty: " << empty << std::endl;
  std::cout << "Lo6: " << lo_6 << std::endl;
  HWAddress<6> hw_addr("01:de:22:01:09:af");

  std::cout << hw_addr << std::endl;
  std::cout << std::hex;
  // prints individual bytes
  for (auto i : hw_addr) {
    std::cout << (int)i << std::endl;
  }

  IPv4Range range1 = IPv4Address("192.168.1.0") / 24;

  IPv4Range range2 = IPv4Range::from_mask("172.168.1.0", "255.255.255.0");
  IPv6Range range3 = IPv6Address("dead::") / 120;
  IPv6Range range4 = IPv6Range::from_mask("dead::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00");

  IPv4Range range = IPv4Address("192.168.1.0") / 29;
  range.contains("192.168.1.250");
  range.contains("192.168.0.100");

  std::cout << std::dec;
  for (const auto& addr : range) {
    std::cout << addr << std::endl;
  }

  // Some OUI which belongs to Intel
  auto range22 = HWAddress<6>("00:19:D1:00:00:00") / 24;

  // Does this address belong to Intel?
  if (range22.contains("00:19:d1:22:33:44")) {
    std::cout << "It's Intel!" << std::endl;
  }

   // We'll write packets to /tmp/test.pcap. Use EthernetII as the link
 // layer protocol.
  PacketWriter writer("./tmp/test2.pcap", DataLinkType<EthernetII>());

  // Now create another writer, but this time we'll use RadioTap.
  PacketWriter other_writer("./tmp/test.pcap", DataLinkType<RadioTap>());

  // A vector containing one EthernetII PDU.
  std::vector<EthernetII> vec(1, EthernetII("00:da:fe:13:ad:fa"));

  // Write the PDU(s) in the vector(only one, in this case).
  writer.write(vec.begin(), vec.end());

  // Write the same PDU once again, using another overload.
  writer.write(vec[0]);

  // Intro END
  // Send a packet
  NetworkInterface def_interface = NetworkInterface::default_interface();
  NetworkInterface::Info def_information = def_interface.addresses();
  EthernetII ethernet;
  ethernet = EthernetII("77:22:33:11:ad", def_information.hw_addr) /
    IP("192.168.0.1", def_information.ip_addr) /
    TCP(13, 15) /   // 13 destination port, 15 src port
    RawPDU("Hello payload");
  PacketSender sender;
  sender.send(ethernet, def_interface);

  // Sniffing with config
  SnifferConfiguration config;
  config.set_filter("port 80");
  config.set_promisc_mode(true);
  config.set_snap_len(400);

  NetworkInterface iface = NetworkInterface::default_interface();
  Sniffer sniffer(iface.name());
  auto a = iface.friendly_name();
  cout << endl << std::string(a.begin(), a.end()) << endl;
  // Construct a Sniffer object, using the configuration above.
  Sniffer sniffer2(NetworkInterface::default_interface().name(), config);

  for (auto x : NetworkInterface::all())
  {
    auto a = x.friendly_name();
    cout << std::string(a.begin(), a.end()) << endl;
  }

  // Loop sniffing
  SnifferConfiguration configloop;
  configloop.set_promisc_mode(true);
  configloop.set_filter("ip src 192.168.0.102");
  Sniffer snifferloop(NetworkInterface::default_interface().name(), configloop);
  //snifferloop.sniff_loop(doo);

  // Packet object
  std::vector<Packet> vt;

  std::string eth0(NetworkInterface::default_interface().name());
  Sniffer snifferPacket(eth0);
  while (vt.size() != 10) {
    // next_packet returns a PtrPacket, which can be implicitly converted to Packet.
    vt.push_back(snifferPacket.next_packet());
  }
  // Done, now let's check the packets
  for (const auto& packet : vt) {
    // Is there an IP PDU somewhere?
    if (packet.pdu()->find_pdu<IP>()) {
      // Just print timestamp's seconds and IP source address
      std::cout << "At: " << packet.timestamp().seconds()
        << " - " << packet.pdu()->rfind_pdu<IP>().src_addr()
        << std::endl;
    }
  }

  //Reading PCAP file
  size_t counter(0);
  FileSniffer snifferFile("./tmp/test2.pcap");
  snifferFile.sniff_loop([&counter](const PDU&) {
    counter++;
    // Always keep looping. When the end of the file is found, 
    // our callback will simply not be called again.
    return true;
    });
  //snifferPacket.sniff_loop(handler); searching for 10 DNS packets
  std::cout << "There are " << counter << " packets in the pcap file\n";
  
  // ARP
  // The address to resolve
  IPv4Address to_resolve("192.168.0.2");
  // The interface we'll use, since we need the sender's HW address
  NetworkInterface ifacen(to_resolve);
  // The interface's information
  auto info = ifacen.addresses();
  // Make the request
  EthernetII ethArp = ARP::make_arp_request(to_resolve, info.ip_addr, info.hw_addr);

  // The sender
  PacketSender senderArp;
  // Send and receive the response.
  std::unique_ptr<PDU> response(senderArp.send_recv(ethArp, ifacen));
  // Did we receive anything?
  if (response) {
    const ARP& arp = response->rfind_pdu<ARP>();
    std::cout << "Hardware address: " << arp.sender_hw_addr() << std::endl;
  }
  //
  // The sender
  PacketSender sender11(NetworkInterface::default_interface());
  // Will throw std::runtime_error if resolving fails
  HWAddress<6> addr = Utils::resolve_hwaddr("192.168.0.1", sender11);
  std::cout << "Hardware address: " << addr << std::endl;
  
  // The sender
  PacketSender senderPack;
  // The SYN to be sent.
  IP pkt = IP("192.168.0.1") / TCP(22, 1337);
  pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);

  // Send and receive the response.
  std::unique_ptr<PDU> responsePack(senderPack.send_recv(pkt));
  // Did we receive anything?
  if (responsePack) {
    TCP& tcp = responsePack->rfind_pdu<TCP>();
    if (tcp.get_flag(TCP::RST)) {
      std::cout << "Port is closed!" << std::endl;
    }
    else {
      std::cout << "Port is open!" << std::endl;
    }
  }

  //
  // The sender
  PacketSender senderP;
  // The DNS request
  IP pakt = IP("8.8.8.8") / UDP(53, 1337) / DNS();
  // Add the query
  pakt.rfind_pdu<DNS>().add_query({ "www.google.com", DNS::A, DNS::INTERNET });
  // We want the query to be resolverd recursively
  pakt.rfind_pdu<DNS>().recursion_desired(1);

  // Send and receive the response.
  std::unique_ptr<PDU> responsePP(senderP.send_recv(pakt, def_interface));
  // Did we receive anything?
  if (responsePP) {
    // Interpret the response
    DNS dns = responsePP->rfind_pdu<RawPDU>().to<DNS>();
    // Print responses
    for (const auto& record : dns.answers()) {
      std::cout << record.dname() << " - " << record.data() << std::endl;
    }
  }
  WSACleanup();
  return 0;
}