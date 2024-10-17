#include <pcap.h> // to capture and analyze packets 
#include <stdio.h> 
#include <netinet/in.h> // for IP addresses
#include <netinet/ip.h> // for IP packets
#include <string.h>  // for strrchr()
#include <stdlib.h>  // for atoi()

/* Used this for macOS instead of <linux/if_ether.h> */
#include <net/ethernet.h> // for Ethernet headers

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // space in memory to store err messages
    pcap_t *handle; // store the handle to the .pcap file
    const unsigned char *packet; // store the data of each packet
    struct pcap_pkthdr header; // stores metadata about each packet

    /* used struct ip instead of struct iphdr */
    struct ip *ip_header; // store the IP header of packet which contains the source and destination IP addresses
    int packet_count = 0;

    int last_octet_counts[256] = {0};  // Array to count occurrences of last octet values

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));

        /* convert the IP address to a string to parse it */
        char *ip_str = inet_ntoa(ip_header->ip_dst);

        /* find the last occurrence of the dot to extract the octet */
        char *last_octet_str = strrchr(ip_str, '.');
      
        /* move the pointer to the part after the last octet */
        last_octet_str++;  

        /* convert the last octet to an integer */
        int last_octet = atoi(last_octet_str);

        /* increment the count for the corresponding last octet value */
        last_octet_counts[last_octet]++;

        // printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst));
    }

    pcap_close(handle);

    /* print the occurrences of each last octet value after processing them into the array */
    for (int i = 0; i < 256; i++) {
        if (last_octet_counts[i] > 0) {
            printf("Last octet %d: %d\n", i, last_octet_counts[i]);
        }
    }
    
    return 0;
}
