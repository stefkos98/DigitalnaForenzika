#pragma once
#ifndef TINS_STATIC
#define TINS_STATIC
#endif
#include <tins/tins.h>
#include <map>
#include <iostream>
#include <functional>

using std::cout;
using std::endl;
using std::map;
using std::bind;

using namespace Tins;

class ArpMonitor {
public:
  ArpMonitor();

  void run(Sniffer& sniffer);
  void run(FileSniffer& sniffer);
  int getNumberOfPackets();
private:
  bool callback(const PDU& pdu);

  map<IPv4Address, HWAddress<6>> addresses;
  int iFoundedPackets;
};