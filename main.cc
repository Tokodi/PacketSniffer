#include <pcap.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using pcapHandlePtr = pcap_t*;


std::string getDefaultInterfaceName() {
    char* interfaceName;
    char errBuf[PCAP_ERRBUF_SIZE];

    interfaceName = pcap_lookupdev(errBuf);
    if (interfaceName == NULL) {
        std::cout << "Could not find default device: " << errBuf << std::endl;
        std::cout << "Terminating program..." << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Interface name: " << interfaceName << std::endl;
    return std::string(interfaceName);
}

pcapHandlePtr getInterfaceHandler(std::string interfaceName) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errBuf);

    if (handle == NULL) {
        std::cout << "Could not open interface for reading." << std::endl;
        std::cout << errBuf << std::endl;
        exit(EXIT_FAILURE);
    }

    return handle;
}

enum class Protocol {ETHERNET, IPv4, IPv6, TCP, UDP, UNKNOWN};
struct Packet {
    Packet (Protocol p, const u_char* l, int o) : protocol(p), payload(l), dataOffset(o) {}
    Packet& operator=(const Packet& other) {
        if(&other == this)
            return *this;

        protocol = other.protocol;
        payload = other.payload;
        dataOffset = other.dataOffset;

        return *this;
    }

    Protocol protocol;
    const u_char* payload;
    int dataOffset;
};

Packet processEthernetHeader(Packet packet) {
    std::cout << "Processing ethernet header..." << std::endl;
    const ether_header* ethHdr = (const ether_header*) packet.payload;

    //TODO: Add more protocols
    Protocol protocol = Protocol::UNKNOWN;
    switch (ethHdr->ether_type) {
        //TODO: understand this
        //case ETHERTYPE_IP:
        case 8:
            protocol = Protocol::IPv4;
            break;
        default:
            std::cout << "Unkown protocol at ethernet level" << std::endl;
            break;
    }

    return Packet(protocol, packet.payload + ETHER_HDR_LEN, (packet.dataOffset + ETHER_HDR_LEN));
}

Packet processIPv4Header(Packet packet) {
    std::cout << "processing IPv4 header..." << std::endl;
    const struct ip* ipHdr = reinterpret_cast<const struct ip*>(packet.payload);

    static char srcIPv4Address[INET_ADDRSTRLEN];
    static char dstIPv4Address[INET_ADDRSTRLEN];
    if ((inet_ntop(AF_INET, &ipHdr->ip_src, srcIPv4Address, sizeof(srcIPv4Address)) != nullptr) &&
        (inet_ntop(AF_INET, &ipHdr->ip_dst, dstIPv4Address, sizeof(dstIPv4Address)) != nullptr)) {
        std::cout << "Source: " << srcIPv4Address << std::endl;
        std::cout << "Destination: " << dstIPv4Address << std::endl;
    } else {
        std::cout << "Could not parse IPv4 address" << std::endl;
    }

    //TODO: Add more protocols
    Protocol protocol = Protocol::UNKNOWN;
    switch ((int)(ipHdr->ip_p)) {
        //TODO: some macros would be wonderful
        case 6:
            protocol = Protocol::TCP;
            break;
//        case 17:
//            protocol = Protocol::UDP;
//            break;
        default:
            std::cout << "Unkown protocol at IPv4 level" << std::endl;
            break;;
    }

    uint8_t ipHdrLength = ipHdr->ip_hl * 4;
    if (ipHdrLength < 20) {
        std::cout << "Invalid IP header length" << std::endl;
    }

    return Packet(protocol, packet.payload + ipHdrLength, (packet.dataOffset + ipHdrLength));
}

Packet processTCPProtocol(Packet packet) {
    std::cout << "processing TCP header..." << std::endl;
    const struct tcphdr* tcpHdr = reinterpret_cast<const struct tcphdr*>(packet.payload);

    std::cout << "Source port: " << tcpHdr->th_sport << std::endl;
    std::cout << "Destination port: " << tcpHdr->th_dport << std::endl;
    std::cout << "Sequence number: " << (unsigned)tcpHdr->seq << std::endl;
    std::cout << "Ack Sequence number: " << (unsigned)tcpHdr->ack_seq << std::endl;

    std::cout << "TCP flags: ";
    if ((tcpHdr->th_flags & TH_FIN) == TH_FIN) {
        std::cout << "finish ";
    }

    if ((tcpHdr->th_flags & TH_SYN) == TH_SYN) {
        std::cout << "syncronization ";
    }

    if ((tcpHdr->th_flags & TH_RST) == TH_RST) {
        std::cout << "reset ";
    }

    if ((tcpHdr->th_flags & TH_PUSH) == TH_PUSH) {
        std::cout << "push ";
    }

    if ((tcpHdr->th_flags & TH_ACK) == TH_ACK) {
        std::cout << "acknowledgement";
    }

    if ((tcpHdr->th_flags & TH_URG) == TH_URG) {
        std::cout << "urgent ";
    }

//    if ((tcpHdr->th_flags & TH_ECE) == TH_ECE) {
//        std::cout << "ECE ";
//    }
//
//    if ((tcpHdr->th_flags & TH_CWR) == TH_CWR) {
//        std::cout << "congestion window reduced ";
//    }
    std::cout << std::endl;

    uint8_t tcpHdrLength = tcpHdr->th_off * 4;
    if (tcpHdrLength < 20) {
        std::cout << "Invalid TCP header length" << std::endl;
    }

    return Packet(Protocol::UNKNOWN, packet.payload + tcpHdrLength, (packet.dataOffset + tcpHdrLength));
}

void processPacket(u_char*, const struct pcap_pkthdr *header, const u_char* pkt) {
    std::cout << "Packet caught [length: " << header->len << "]" << std::endl;

    Packet packet(Protocol::ETHERNET, pkt, 0);
    while (packet.protocol != Protocol::UNKNOWN) {
        //TODO: Add more protocols
        switch (packet.protocol) {
            case Protocol::ETHERNET:
                packet = processEthernetHeader(packet);
                break;
            case Protocol::IPv4:
                packet = processIPv4Header(packet);
                break;
            case Protocol::TCP:
                packet = processTCPProtocol(packet);
                break;
            default:
                std::cout << "Unknown protocol at process level" << std::endl;
                break;
        }
    }

    std::cout << std::endl;
    std::cout << "Packet length: " << header->len << std::endl;
    std::cout << "Payload offset: " << packet.dataOffset << std::endl;
    std::cout << "Payload length: " << header->len - packet.dataOffset << std::endl;
    std::cout << "Payload: " << std::string((const char*)packet.payload, header->len - packet.dataOffset) << std::endl;

    std::cout << std::endl << "==============================" << std::endl << std::endl;
}

int main()
{
    std::string interfaceName = getDefaultInterfaceName();
    pcapHandlePtr interfaceHandler = getInterfaceHandler(interfaceName);

    if (pcap_datalink(interfaceHandler) != DLT_EN10MB) {
        std::cout << "Device " << interfaceName << " does not provide WiFi headers - not supported" << std::endl;
        exit(EXIT_FAILURE);
    }

    char errBuf[PCAP_ERRBUF_SIZE];          /* Error string */
    bpf_u_int32 mask;                       /* The netmask of our sniffing device */
    bpf_u_int32 net;                        /* The IP of our sniffing device */

    if (pcap_lookupnet(interfaceName.c_str(), &net, &mask, errBuf) == -1) {
        std::cout << "Could not get netmask for interface " << interfaceName << std::endl;
        net = 0;
        mask = 0;
        exit(EXIT_FAILURE);
    }

    struct bpf_program fp;              /* The compiled filter expression */
    //char filterExp[] = "port 80";       /* The filter expression */
    char filterExp[] = "port 443";       /* The filter expression */

    if (pcap_compile(interfaceHandler, &fp, filterExp, 0, net) == -1) {
        std::cout << "Could not parse filter " << pcap_geterr(interfaceHandler) << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(interfaceHandler, &fp) == -1) {
        std::cout << "Could not install filter " << pcap_geterr(interfaceHandler) << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "==============================" << std::endl;

    int rc = pcap_loop(interfaceHandler, 30, processPacket, NULL);
    if (rc != 0) {
        std::cout << "Error happened while capturing packets" << std::endl;
    }

    pcap_close(interfaceHandler);

    std::cout << "Terminating program..." << std::endl;

    return 0;
}

