#pragma once
#ifndef TINS_STATIC
#define TINS_STATIC
#endif
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <cstdint>
#include <random>
#include <map>
#include <algorithm>
#include <atomic>
#include <limits>
#include <mutex>
#include <tins/tins.h>

using std::cout;
using std::endl;
using std::move;
using std::map;
using std::min;
using std::setw;
using std::atomic;
using std::runtime_error;
using std::string;
using std::to_string;
using std::thread;
using std::this_thread::sleep_for;
using std::lock_guard;
using std::mutex;
using std::random_device;
using std::numeric_limits;
using std::bind;
using std::chrono::milliseconds;

using namespace Tins;
typedef std::map<uint16_t, IPv4Address> result_type;
typedef map<uint16_t, size_t> ttl_map;

class Traceroute {
public:
  Traceroute(NetworkInterface interface, IPv4Address address);
  result_type trace();

private:

  void send_packets(PacketSender& sender);
  bool sniff_callback(PDU& pdu);

  NetworkInterface iface;
  IPv4Address addr;
  atomic<bool> running;
  ttl_map ttls;
  result_type results;
  mutex lock;
  uint16_t sequence;
  int lowest_dest_ttl;
};