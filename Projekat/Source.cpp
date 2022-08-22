// {0D634653-9EBC-4CE4-8E8E-710A04F2E9C2} ethernet
// {CEFB2FC3-E47E-4FA3-BBF3-7ACD4D19970E} wifi
// www.facebook.com 31.13.84.36
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
#ifndef TINS_STATIC
#define TINS_STATIC
#endif
#define NOMINMAX

#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <tins/network_interface.h>
#include <iomanip>
#include "Traceroute.h"
#include "ArpMonitor.h"
#include "Defragmenter.h"
#include <tins\tcp_ip\stream_follower.h>
#include <regex>

using std::cout;
using std::wcout;
using std::endl;
using std::string;
using std::ostringstream;

using namespace Tins;
using namespace std;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::TCPIP::Stream;
//******************* HTTP REQUEST_RESPONSE************
// This example captures and follows TCP streams seen on port 80. It will
// wait until both the client and server send data and then apply a regex
// to both payloads, extrating some information and printing it.

const size_t MAX_PAYLOAD = 2 * 1024 * 1024;
int MIN_IMAGE_LIMIT = -1;
// The regex to be applied on the request. This will extract the HTTP
// method being used, the request's path and the Host header value.
regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
// The regex to be applied on the response. This finds the response code.
regex response_regex("HTTP/[^ ]+ ([\\d]+)");

regex image_regex("(C|c)ontent-(T|t)ype: .*(;|\r\n)");
regex imagetype_regex("image");
regex length_regex("(C|c)ontent-(L|l)ength: (0|[0-9]+)");

void getPicture(char* buffer, int bReceived, const int& bSize, string type);

void on_server_data(Stream& stream) {
  match_results<Stream::payload_type::const_iterator> client_match;
  match_results<Stream::payload_type::const_iterator> server_match;
  match_results<Stream::payload_type::const_iterator> length_match;
  match_results<Stream::payload_type::const_iterator> type_match;

  const Stream::payload_type& client_payload = stream.client_payload();
  const Stream::payload_type& server_payload = stream.server_payload();
  // Run the regexes on client/server payloads
  bool valid = regex_search(server_payload.begin(), server_payload.end(), server_match, response_regex)
    && regex_search(client_payload.begin(), client_payload.end(), client_match, request_regex);
  if (valid) {
    regex_search(server_payload.begin(), server_payload.end(), length_match, length_regex);
    regex_search(server_payload.begin(), server_payload.end(), type_match, image_regex);

    // Extract all fields
    string method = string(client_match[1].first, client_match[1].second);
    string url = string(client_match[2].first, client_match[2].second);
    string host = string(client_match[3].first, client_match[3].second);
    string response_code = string(server_match[1].first, server_match[1].second);
    string content_length = string(length_match[0].first, length_match[0].second);
    content_length = (content_length.compare("") != 0) ? content_length : string("There isn't a length attribute");
    string response_type = string(type_match[0].first, type_match[0].second);
    response_type = (response_type.compare("") != 0) ? response_type : string("There isn't a content-type attribute");

    if (MIN_IMAGE_LIMIT > -1)
    {
      match_results<string::const_iterator> imagetype_match;
      size_t sImagePos = response_type.find("image");
      if (sImagePos != string::npos)
      {
        std::string response_size = content_length.substr((size_t)16, content_length.length() - ((size_t)16));
        int iResponseSize = -1;
        try {
          iResponseSize = stoi(response_size);
        }
        catch (...)
        {
          int iResponseSize = -1;
        }
        if (iResponseSize > MIN_IMAGE_LIMIT)
        {
          string clientdata(stream.client_payload().begin(), stream.client_payload().end());
          string data(stream.server_payload().begin(), stream.server_payload().end());
          cout << method << " http://" << host << url << " -> " << response_code << endl;
          cout << CYAN << "LENGTH: " << content_length << endl << RESET <<
            BLUE << "TYPE: " << response_type << endl << RESET <<
            BOLDGREEN << "SERVER DATA: " << data << endl << RESET <<
            GREEN << "CLIENT DATA: " << clientdata << endl << RESET;
          std::flush(std::cout);
          int velicina;
          char* char_arr;
          char_arr = &data[0];
          std::string extension = "jpeg";
          switch (response_type[sImagePos + 6])
          {
          case 'p': extension = "png"; break;
          case 'b': extension = "bmp"; break;
          }
          getPicture(char_arr, data.size(), velicina, extension);
        }
      }
    }
    else {
      cout << method << " http://" << host << url << " -> " << response_code << endl;
      cout << CYAN << "LENGTH: " << content_length << endl << RESET <<
        BLUE << "TYPE: " << response_type << endl << RESET;
      std::flush(std::cout);
    }
    stream.ignore_client_data();
    stream.ignore_server_data();
  }

  if (stream.server_payload().size() > MAX_PAYLOAD) {
    stream.ignore_server_data();
  }
}

void on_client_data(Stream& stream) {
  // Don't hold more than 1mb of data from the client's flow
  if (stream.client_payload().size() > MAX_PAYLOAD) {
    stream.ignore_client_data();
  }
}

void on_connection_closed(Stream& stream)
{
  stream.ignore_client_data();
  stream.ignore_server_data();
}
void on_new_connection(Stream& stream) {
  stream.client_data_callback(&on_client_data);
  stream.server_data_callback(&on_server_data);
  // Don't automatically cleanup the stream's data, as we'll manage
  // the buffer ourselves and let it grow until we see a full request
  // and response
  stream.auto_cleanup_payloads(false);
  stream.stream_closed_callback(&on_connection_closed);

}
//******************* TCP SNIFFING *****************
// This example takes an interface and a port as an argument and
// it listens for TCP streams on the given interface and port.
// It will reassemble TCP streams and show the traffic sent by
// both the client and the server.

// Convert the client endpoint to a readable string
string client_endpoint(const Stream& stream) {
  ostringstream output;
  // Use the IPv4 or IPv6 address depending on which protocol the 
  // connection uses
  if (stream.is_v6()) {
    output << stream.client_addr_v6();
  }
  else {
    output << stream.client_addr_v4();
  }
  output << ":" << stream.client_port();
  return output.str();
}

string server_endpoint(const Stream& stream) {
  ostringstream output;
  if (stream.is_v6()) {
    output << stream.server_addr_v6();
  }
  else {
    output << stream.server_addr_v4();
  }
  output << ":" << stream.server_port();
  return output.str();
}

string stream_identifier(const Stream& stream) {
  ostringstream output;
  output << client_endpoint(stream) << " - " << server_endpoint(stream);
  return output.str();
}

// Whenever there's new client data on the stream, this callback is executed.
void on_client_dataTCP(Stream& stream) {
  string data(stream.client_payload().begin(), stream.client_payload().end());

  cout << "NEW CLIENT DATA : " << client_endpoint(stream) << " >> "
    << server_endpoint(stream) << ": " << endl << data << endl;
}

// Whenever there's new server data on the stream, this callback is executed.
void on_server_dataTCP(Stream& stream) {
  string data(stream.server_payload().begin(), stream.server_payload().end());

  cout << "NEW SERVER DATA : " << server_endpoint(stream) << " >> "
    << client_endpoint(stream) << ": " << endl << data << endl;
}

// When a connection is closed, this callback is executed.
void on_connection_closedTCP(Stream& stream) {
  cout << "[+] Connection closed: " << stream_identifier(stream) << endl;
}

// When a new connection is captured, this callback will be executed.
void on_new_connectionTCP(Stream& stream) {
  if (stream.is_partial_stream()) {
    // We found a partial stream. This means this connection/stream had
    // been established before we started capturing traffic.
    // In this case, we need to allow for the stream to catch up, as we
    // may have just captured an out of order packet and if we keep waiting
    // for the holes to be filled, we may end up waiting forever.
    // Calling enable_recovery_mode will skip out of order packets that
    // fall withing the range of the given window size.
    // See Stream::enable_recover_mode for more information
    cout << "[+] New connection " << stream_identifier(stream) << endl;
    stream.enable_recovery_mode(1024 * 1024);
  }
  else {
    // Print some information about the new connection
    cout << "[+] New connection " << stream_identifier(stream) << endl;
  }

  // Now configure the callbacks on it.
  // First, we want on_client_data to be called every time there's new client data
  stream.client_data_callback(&on_client_dataTCP);

  // Same thing for server data, but calling on_server_data
  stream.server_data_callback(&on_server_dataTCP);

  // When the connection is closed, call on_connection_closed
  stream.stream_closed_callback(&on_connection_closedTCP);
}

//******************* DNS QUERIES callback function ********************
bool DNSCallback(const PDU& pdu) {
  // EthernetII / IP / UDP / RawPDU

  DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
  // Retrieve the queries and print the domain name:
  for (const auto& query : dns.queries()) {
    cout << BLUE << "[DNS QUERY] " << query.dname() << RESET << std::endl;
  }
  return true;
}

char* removeHTTPHeader(char* buffer, int& bodySize) {
  char* t = strstr(buffer, "\r\n\r\n");
  t = t + 4;

  for (auto it = buffer; it != t; ++it) {
    ++bodySize;
  }

  return t;
}

void getPicture(char* buffer, int bReceived, const int& bSize, string type) {
  static int i = 0;
  std::ofstream file("picture" + std::to_string(i++) + "." + type, std::ofstream::binary | std::ofstream::out);

  int bodySize = 0;

  char* t = removeHTTPHeader(buffer, bodySize);
  bodySize = bReceived - bodySize;

  file.write(t, bodySize);

  file.close();
}

//**************

int main()
{
  NetworkInterface niDefaultInterface = NetworkInterface::from_index(3); // Ethernet
  if (!niDefaultInterface.is_up())
  {
    niDefaultInterface = NetworkInterface::from_index(17); // Wi-Fi
  }
  while (true)
  {
    cout << "Welcome to Network Analyzer app!\n";
    cout << "What would you like to do?\n";
    cout << " 1 - Trace Route \n";
    cout << " 2 - Real-time sniffing \n";
    cout << " 3 - Analyzing traffic from file \n";
    cout << " 4 - Check interfaces status \n";
    cout << " 5 - Exit \n";
    int iAnswer = 0;
    while (iAnswer == 0)
    {
      cout << "Your answer: ";
      std::cin.clear();
      std::string sAnswer;
      std::getline(std::cin, sAnswer);
      try
      {
        iAnswer = stoi(sAnswer);
      }
      catch (...)
      {
        iAnswer = 0;
      }
      if (iAnswer < 1 || iAnswer > 5)
      {
        cout << "Invalid option. Try again.\n";
        iAnswer = 0;
      }
    }
    switch (iAnswer)
    {
    case 1: {
      try {
      std:string sIpAddres;
        cout << "Enter IPV4 address for which you want to trace route\n";
        getline(std::cin, sIpAddres);
        IPv4Address addr = sIpAddres;
        Traceroute tracer(addr, addr);
        auto results = tracer.trace();
        if (results.empty()) {
          cout << "No hops found" << endl;
        }
        else {
          cout << "Results: " << endl;
          for (const auto& entry : results) {
            cout << setw(2) << entry.first << " - " << entry.second << endl;
          }
        }
      }
      catch (runtime_error& ex) {
        cout << "Error - " << ex.what() << endl;
        return 2;
      }
      break;
    }
    case 2: {
      cout << "Real time sniffing selected!!\n";
      cout << "What would you like to do?\n";
      cout << " 1 - Trace DNS queries \n";
      cout << " 2 - Trace TCP traffic \n";
      cout << " 3 - Trace HTTP requests and responses \n";
      cout << " 4 - Trace images sent through HTTP \n";
      cout << " 5 - Trace ARP \n";
      cout << " 6 - Exit \n";
      int iAnswer = 0;
      while (iAnswer == 0)
      {
        cout << "Your answer: ";
        std::cin.clear();
        std::string sAnswer;
        std::getline(std::cin, sAnswer);
        try
        {
          iAnswer = stoi(sAnswer);
        }
        catch (...)
        {
          iAnswer = 0;
        }
        if (iAnswer < 1 || iAnswer > 6)
        {
          cout << "Invalid option. Try again.\n";
          iAnswer = 0;
        }
      }
      switch (iAnswer)
      {
      case 1: {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("udp and dst port 53");
        Sniffer sniffer(niDefaultInterface.name(), config);
        sniffer.sniff_loop(DNSCallback);
        return 0;
      }
      case 2: {
        iAnswer = 0;
        while (iAnswer == 0 || iAnswer > 65535)
        {
          cout << "Select port on which to sniff packet: ";
          std::cin.clear();
          std::string sAnswer;
          std::getline(std::cin, sAnswer);
          try
          {
            iAnswer = stoi(sAnswer);
          }
          catch (...)
          {
            iAnswer = 0;
          }
        }

        try {
          // Construct the sniffer configuration object
          SnifferConfiguration config;
          // Only capture TCP traffic sent from/to the given port
          config.set_filter("tcp port " + to_string(iAnswer));
          Sniffer sniffer(niDefaultInterface.name(), config);

          wcout << "Starting capture on interface " << niDefaultInterface.friendly_name() << endl;

          // Now construct the stream follower
          Tins::TCPIP::StreamFollower follower;

          follower.new_stream_callback(&on_new_connectionTCP);

          // Allow following partial TCP streams (e.g. streams that were
          // open before the sniffer started running)
          follower.follow_partial_streams(true);

          // Now start capturing. Every time there's a new packet, call 
          // follower.process_packet
          sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
            });
        }
        catch (exception& ex) {
          cerr << "Error: " << ex.what() << endl;
          return 1;
        }
      }
      case 3: {
        try {
          SnifferConfiguration config;
          config.set_immediate_mode(true);
          config.set_filter("tcp port 80");
          Sniffer sniffer(niDefaultInterface.name(), config);
          wcout << "Starting capture on interface " << niDefaultInterface.friendly_name() << endl;

          StreamFollower follower;
          follower.new_stream_callback(&on_new_connection);
          sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
            });
        }
        catch (exception& ex) {
          cerr << "Error: " << ex.what() << endl;
          return 1;
        }
        return 0;
      }
      case 4: {
        try {
          MIN_IMAGE_LIMIT = -1;
          cout << "Write minimum size in bytes for detection" << endl;
          while (MIN_IMAGE_LIMIT <= -1) {

            std::string sImageLimit;
            std::getline(std::cin, sImageLimit);
            try
            {
              MIN_IMAGE_LIMIT = stoi(sImageLimit);
            }
            catch (...)
            {
              MIN_IMAGE_LIMIT = -1;
              cout << "Invalid input. Try again!" << endl;
            }
          }
          SnifferConfiguration config;
          config.set_immediate_mode(true);
          config.set_filter("tcp port 80");
          Sniffer sniffer(niDefaultInterface.name(), config);
          wcout << "Starting capture on interface " << niDefaultInterface.friendly_name() << endl;

          StreamFollower follower;
          follower.new_stream_callback(&on_new_connection);
          sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
            });
        }
        catch (exception& ex) {
          cerr << "Error: " << ex.what() << endl;
          return 1;
        }
      }
      case 5: {
        ArpMonitor monitor;
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("arp");
        NetworkInterface iface = NetworkInterface::default_interface();
        try {
          Sniffer sniffer(niDefaultInterface.name(), config);
          monitor.run(sniffer);
        }
        catch (std::exception& ex) {
          std::cerr << "Error: " << ex.what() << std::endl;
        }
        return  0;
      }
      }
      break;
    }
    case 3: {
      cout << "Sniffing from file selected!!\n";
      cout << "Choose file for sniffing (that file should be in tmp folder of the project) \n";
      std::string sFile;
      std::getline(std::cin, sFile);
      //Reading PCAP file
      size_t counter(0);
      FileSniffer snifferFile("./tmp/" + sFile);
      snifferFile.sniff_loop([&counter](const PDU&) {
        counter++;
        // Always keep looping. When the end of the file is found, 
        // our callback will simply not be called again.
        return true;
        });
      std::cout << "There are " << counter << " packets in the pcap file\n";

      cout << "What would you like to do?\n";
      cout << " 1 - Trace DNS queries \n";
      cout << " 2 - Trace TCP packets \n";
      cout << " 3 - IP packets fragmentation \n";
      cout << " 4 - Trace ARP \n";
      cout << " 5 - Exit \n";
      int iAnswer = 0;
      while (iAnswer == 0)
      {
        cout << "Your answer: ";
        std::cin.clear();
        std::string sAnswer;
        std::getline(std::cin, sAnswer);
        try
        {
          iAnswer = stoi(sAnswer);
        }
        catch (...)
        {
          iAnswer = 0;
        }
        if (iAnswer < 1 || iAnswer > 5)
        {
          cout << "Invalid option. Try again.\n";
          iAnswer = 0;
        }
      }
      switch (iAnswer)
      {
      case 1: {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("udp and dst port 53");
        FileSniffer snifferFileDNS("./tmp/" + sFile, config);
        snifferFileDNS.sniff_loop(DNSCallback);
        break;
      }
      case 2: {
        iAnswer = 0;
        while (iAnswer == 0 || iAnswer > 65535)
        {
          cout << "Select port on which to sniff packet: ";
          std::cin.clear();
          std::string sAnswer;
          std::getline(std::cin, sAnswer);
          try
          {
            iAnswer = stoi(sAnswer);
          }
          catch (...)
          {
            iAnswer = 0;
          }
        }

        try {
          // Construct the sniffer configuration object
          SnifferConfiguration config;
          // Only capture TCP traffic sent from/to the given port
          config.set_filter("tcp port " + to_string(iAnswer));
          Sniffer sniffer(niDefaultInterface.name(), config);

          cout << "Starting capture from file " << sFile << endl;

          FileSniffer snifferFileDNS("./tmp/" + sFile, config);
          int counter = 0;
          snifferFileDNS.sniff_loop([&counter](PDU& packet) {
            counter++;
            return true;
            });
          cout << "Total packets: " << counter << endl;
        }
        catch (exception& ex) {
          cerr << "Error: " << ex.what() << endl;
          return 1;
        }
        break;
      }
      case 3: {
        try {

          cout << "Source file name: ";
          std::string sSource;
          std::getline(std::cin, sSource);
          cout << "Destination file name: ";
          std::string sDestination;
          std::getline(std::cin, sDestination);
          // Build the defragmented
          Defragmenter defragmenter("./tmp/" + sSource, "./tmp/" + sDestination);
          cout << "Processing " << sSource << endl;
          cout << "Writing results to " << sDestination << endl;

          // Run!
          defragmenter.run();
          cout << "Done" << endl;
          cout << "Reassembled: " << defragmenter.total_packets_reassembled()
            << " packet(s)" << endl;
          cout << "Fragmented: " << defragmenter.total_packets_fragmented() << " packet(s)" << endl;
        }
        catch (exception& ex) {
          cerr << "Error: " << ex.what() << endl;
        }
        break;
      }

      case 4:
      {
        ArpMonitor monitor;
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("arp");
        try {
          FileSniffer snifferFileARP("./tmp/" + sFile, config);
          monitor.run(snifferFileARP);
          cout << "Total packets: " << monitor.getNumberOfPackets() << " packet(s)" << endl;

        }
        catch (std::exception& ex) {
          break;
        }
        break;
      }
      default:
        cout << "Goodbye!\n";
        return 0;
      }
      break;
    }
    case 4: {
      for (const NetworkInterface& niFace : NetworkInterface::all())
      {
        string sName = niFace.name();
        string sStatus = niFace.is_up() ? "up" : "down";
        NetworkInterface::Info iInfo = niFace.info();
        cout << "Interface name: " << sName;
        wcout << " (" << niFace.friendly_name() << ")\n";
        cout << "HW address:     " << iInfo.hw_addr << endl;
        cout << "IP address:     " << iInfo.ip_addr << endl;
        cout << "Netmask:        " << iInfo.netmask << endl;
        cout << "Broadcast:      " << iInfo.bcast_addr << endl;
        cout << "Iface index:    " << niFace.id() << endl;
        cout << "Status:         " << "Interface is " << sStatus << endl << endl;
      }
      break;
    }
    default:
      cout << "Goodbye!\n";
      return 0;
    }
          // break;
    }
    return 0;
  }