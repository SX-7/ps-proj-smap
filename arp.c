#include "smap.h"

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60


struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }

    err = 0;
out:
    if (sd > 0) {
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        close(*fd);
    }
    return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd)
{
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        goto out;
    }
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

    ret = 0;

out:
    return ret;
}

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arping(const char *ifname, struct sockaddr_in sa) {
    int ret = -1;

    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src, mac, &ifindex)) {
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        goto out;
    }

    if (send_arp(arp_fd, ifindex, mac, src, sa.sin_addr.s_addr)) {
        goto out;
    }

    while(1) {
        int r = read_arp(arp_fd);
        if (r == 0) {
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}