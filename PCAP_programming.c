#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Function to print Ethernet header
void printEthernetHeader(const unsigned char *packet) {
    struct ether_header *ethHeader = (struct ether_header *)packet;
    printf("Source MAC Address: %s\n", ether_ntoa((struct ether_addr *)ethHeader->ether_shost));
    printf("Destination MAC Address: %s\n", ether_ntoa((struct ether_addr *)ethHeader->ether_dhost));
}

// Function to print IP header
void printIPHeader(const unsigned char *packet) {
    struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    printf("Source IP Address: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("Destination IP Address: %s\n", inet_ntoa(ipHeader->ip_dst));
}

// Function to print TCP header
void printTCPHeader(const unsigned char *packet) {
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
    printf("Destination Port: %d\n", ntohs(tcpHeader->th_dport));
}

// Function to print message
void printMessage(const unsigned char *packet, const struct pcap_pkthdr *packetHeader) {
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    int dataOffset = sizeof(struct ether_header) + sizeof(struct ip) + tcpHeader->th_off * 4;
    int dataLength = packetHeader->len - dataOffset;
    if (dataLength > 0) {
        printf("Message: ");
        for (int i = 0; i < dataLength && i < 20; i++) {
            printf("%02X ", packet[dataOffset + i]);
        }
        printf("\n");
    }
}

// Function to handle packet
void handlePacket(unsigned char *userData, const struct pcap_pkthdr *packetHeader, const unsigned char *packet) {
    printf("--------- Packet Captured ---------\n");
    // Print Ethernet header
    printEthernetHeader(packet);
    // Print IP header
    printIPHeader(packet);
    // Print TCP header
    printTCPHeader(packet);
    // Print message
    printMessage(packet, packetHeader);
    printf("----------------------------------\n");
}

int main() {
    char *device; 
    char errorBuffer[PCAP_ERRBUF_SIZE]; // Error buffer
    pcap_t *handle; // PCAP handler

    // Finding network devices
    pcap_if_t *allDevices, *deviceList;
    
    if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
        printf("Unable to find network devices: %s\n", errorBuffer);
        return 1;
    }

    // Choosing the first network device
    device = allDevices->name;

    // Opening network device
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        printf("Unable to open network device: %s\n", errorBuffer);
        return 1;
    }

    // Starting packet sniffing loop
    pcap_loop(handle, 0, handlePacket, NULL);

    pcap_close(handle);
    return 0;
}

