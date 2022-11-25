// traffic1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdlib.h>
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

bool StartsWith(const std::string& text, const std::string& token)
{
    if (text.length() < token.length()) return false;
    return (text.compare(0, token.length(), token) == 0);
}

const std::string interfaceIPAddr;
const int NumOfPacket = 20;
const std::string output = "outputFile.txt";

* A struct for collecting packet statistics
*/
struct PacketStats
{
    int ethPacketCount;
    int ipv4PacketCount;
    int ipv6PacketCount;
    int tcpPacketCount;
    int udpPacketCount;
    int dnsPacketCount;
    int httpPacketCount;
    int sslPacketCount;

    /**
    * Clear all stats
    */
    void clear() { ethPacketCount = 0; ipv4PacketCount = 0; ipv6PacketCount = 0; tcpPacketCount = 0; udpPacketCount = 0; tcpPacketCount = 0; dnsPacketCount = 0; httpPacketCount = 0; sslPacketCount = 0; }

    /**
    * C'tor
    */
    PacketStats() { clear(); }

    /**
    * Collect stats from a packet
    */
    void consumePacket(pcpp::Packet& packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    /**
    * Print stats to console
    */
    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl
            << "IPv4 packet count:     " << ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << ipv6PacketCount << std::endl
            << "TCP packet count:      " << tcpPacketCount << std::endl
            << "UDP packet count:      " << udpPacketCount << std::endl
            << "DNS packet count:      " << dnsPacketCount << std::endl
            << "HTTP packet count:     " << httpPacketCount << std::endl
            << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

/**
* A callback function for the async capture which is called each time a packet is captured
*/
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    // extract the stats object form the cookie
    PacketStats* stats = (PacketStats*)cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);
}

// create a filter instance to capture only traffic on port 80
pcpp::PortFilter portFilter(80, pcpp::SRC_OR_DST);

// create a filter instance to capture only TCP traffic
pcpp::ProtoFilter protocolFilter(pcpp::TCP);

// create an AND filter to combine both filters - capture only TCP traffic on port 80
pcpp::AndFilter andFilter;
andFilter.addFilter(&portFilter);
andFilter.addFilter(&protocolFilter);]

void ReadConfig() {
    const std::string config = "/path/to/config/config.cfg";

    // Open file
    std::ifstream file(config, std::ifstream::in);
    if (!file.is_open()) return false;

    // Read line by line
    std::string line;
    char hfile[1000];
    if (StartsWith(line, "NUMOBPACKETS")) {
        sscanf(line.data(), "NUMOBPACKETS %s", hfile);
        NumOfPacket = std::stoi(hfile);
    }else if (StartsWith(line, "IPADRESS")) {
        sscanf(line.data(), "IPADRESS %s", hfile);
        interfaceIPAddr = hfile;
    }
}

int main()
{
    ReadConfig();

    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
    if (dev == NULL)
    {
        std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
        return 1;
    }
    // before capturing packets let's print some info about this interface
    std::cout
        << "Interface info:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl // get interface name
        << "   Interface description: " << dev->getDesc() << std::endl // get interface description
        << "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
        << "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::end;

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    // set the filter on the device
    dev->setFilter(andFilter);

    PacketStats stats;

    std::cout << std::endl << "Starting packet capture with a filter in place..." << std::endl;

    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    dev->startCapture(onPacketArrives, &stats);

    // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
    pcpp::multiPlatformSleep(10);

    // stop capturing packets
    dev->stopCapture();

    // print results - should capture only packets which match the filter (which is TCP port 80)
    std::cout << "Results:" << std::endl;
    stats.printToConsole();

    std::cout << std::endl << "Sending " << packetVec.size() << " packets one by one..." << std::endl;

    // go over the vector of packets and send them one by one
    if(packetVec.length() >NumOfPacket ) for(cpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
    {
        // send the packet. If fails exit the application
        if (!dev->sendPacket(**iter))
        {
            std::cerr << "Couldn't send packet" << std::endl;
            return 1;
        }

        std::ifstream outfile(output, std::ifstream::in);
        if (!outfile.is_open()) return false;
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // print source and dest IPs
        cerr
            << "Source IP is '" << srcIP << "'; "
            << "Dest IP is '" << destIP << "'"
            << "devie Mac Adress" << dev->getMacAddress() << ","
            << std::endl;
        outfile.close();
    }
    std::cout << packetVec.size() << " packets sent" << std::endl;

    return 0;
}
