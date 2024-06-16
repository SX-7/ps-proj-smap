#include <stdio.h>           //for printf
#include <string.h>          //memset
#include <sys/socket.h>      //for socket ofcourse
#include <stdlib.h>          //for exit(0);
#include <errno.h>           //For errno - the error number
#include <netinet/tcp.h>     //Provides declarations for tcp header
#include <netinet/udp.h>     //Provides declarations for tcp header
#include <netinet/ip_icmp.h> //Provides declarations for tcp header
#include <netinet/ip.h>      //Provides declarations for ip header
#include <arpa/inet.h>       // inet_addr
#include <unistd.h>          // sleep()
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>

#define TEST_PACKET_SIZE 256
#define FIRST_OCTET 0
#define SECOND_OCTET 1
#define THIRD_OCTET 2
#define FOURTH_OCTET 3
#define TCP_SYN_DISCOVERY 0x01
#define TCP_ACK_DISCOVERY 0x02
#define UDP_DISCOVERY 0x04
#define ICMP_ECHO_DISCOVERY 0x08
/*
    96 bit (12 bytes) pseudo header needed for header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t length;
};

struct octet_store
{
    struct octet
    {
        uint16_t first[256];
        uint16_t second[256];
        uint16_t third[256];
        uint16_t fourth[256];
    } octet;

    struct count
    {
        uint16_t first;
        uint16_t second;
        uint16_t third;
        uint16_t fourth;
    } count;

    struct offset
    {
        uint16_t first;
        uint16_t second;
        uint16_t third;
        uint16_t fourth;
    } offset;
};

//should be packed, if it's not 1 byte, something's wrong with the packing. check compiler
struct port_chunk{
    uint8_t p0 :1;
    uint8_t p1 :1;
    uint8_t p2 :1;
    uint8_t p3 :1;
    uint8_t p4 :1;
    uint8_t p5 :1;
    uint8_t p6 :1;
    uint8_t p7 :1;
};

struct port_store{
    uint32_t offset;
    struct port_chunk chunk[8192];
};

struct address_store{
    uint32_t capacity;
    uint32_t size;
    uint32_t *addresses;
};

struct address_port_status{
    uint32_t address;
    uint16_t port;
    uint16_t status;
};

struct address_port_store{
    uint32_t capacity;
    uint32_t size;
    struct address_port_status *addresses;
};

void sigquit();
// host discovery
int check_adress_up_tcp_ack(int sd, struct sockaddr_in sa, char *source_ip, int source_port);
int check_adress_up_tcp_syn(int sd, struct sockaddr_in sa, char *source_ip, int source_port);
int check_adress_up_udp_port_unreachable(int sd_udp, int sd_icmp, struct sockaddr_in dest_sa, char *source_ip, int source_port);
int check_adress_up_icmp_echo(int sd_sender, int sd_listener, struct sockaddr_in dest_sa, char *source_ip, int source_port);
// utils
unsigned short csum(unsigned short *ptr, int nbytes);
int init_address_positions(struct octet_store * oc);
int add_address_position(int octet, short address, struct octet_store * oc);
int add_address_position_range(int octet, short address_bottom, short address_top_inclusive, struct octet_store * oc );
in_addr_t get_next_address(struct octet_store * oc);
//ports
uint16_t add_port(uint16_t port_index, struct port_store *ps);
uint16_t remove_port(uint16_t port_index, struct port_store *ps);
uint16_t get_port(uint16_t port_index, struct port_store *ps);
u_int16_t add_port_range(uint16_t start_port, uint16_t end_port_inclusive, struct port_store* ps);
u_int16_t remove_port_range(uint16_t start_port, uint16_t end_port_inclusive, struct port_store* ps);
uint16_t get_next_port(struct port_store* ps, uint16_t *port);
//vector kinda
int address_store_init(struct address_store *as, uint32_t init_capacity);
int address_store_get(struct address_store *as, uint32_t index, uint32_t *dest);
int address_store_add(struct address_store *as, uint32_t data);
int address_store_add_if_nexists(struct address_store *as, uint32_t data);
int address_store_check_if_exists(struct address_store *as, uint32_t data);
//other vector
int ap_store_init(struct address_port_store *as, uint32_t init_capacity);
int ap_store_get(struct address_port_store *as, uint32_t index, struct address_port_status *ap);
int ap_store_add(struct address_port_store *as, struct address_port_status ap);
int ap_store_add_if_nexists(struct address_port_store *as, struct address_port_status ap);
int ap_store_check_if_exists(struct address_port_store *as, struct address_port_status ap);
//-header setup
//--tcp
int setup_ip_tcp_header(char *datagram, size_t datagram_max_len, struct sockaddr_in sa, int source_port);
int compute_ip_tcp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa);
//--udp
int setup_ip_udp_header(char *datagram, size_t datagram_max_len, struct sockaddr_in sa, int source_port);
int compute_ip_udp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa);
//--icmp
int setup_ip_icmp_header(char *datagram, size_t datagram_max_len);
int compute_ip_icmp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa);
// int test_arping(const char *ifname, struct sockaddr_in sa);
// scan
int scan_tcp_syn_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port);
int scan_tcp_syn_listen(int sd, struct address_store *as, struct address_port_store *aps, int sender_pid);
//
int run_discovery(struct octet_store *adresses_to_scan,
                  struct port_store *ps_tcp_ack,
                  struct port_store *ps_tcp_syn,
                  struct port_store *ps_udp,
                  struct port_store *ps_icmp_echo,
                  char *source_ip,
                  struct address_store *active_hosts);