#include "smap.h"

int main(int argc, const char **argv)
{
    if (argc < 2)
    {
        printf("Usage:\n");
        printf("%s [options] {interface} {target}\n", argv[0]);
        printf("Host discovery options:\n");
        printf("-PS/-PA/-PU[portlist]: TCP SYN, TCP ACK, UDP discovery to ports\n");
        printf("-PE: ICMP echo discovery\n");
        printf("Port scan options:\n");
        printf("-sS: TCP SYN scan\n");
        printf("Port specification:\n");
        printf("-p <port ranges>: Scan these ports\n");
        return 1;
    }
    else
    {
        // parse input
    }
    // select ip adresses to scan
    struct octet_store *adresses_to_scan;
    adresses_to_scan = malloc(sizeof(struct octet_store));
    init_address_positions(adresses_to_scan);
    add_address_position(FIRST_OCTET, 192, adresses_to_scan);
    add_address_position(SECOND_OCTET, 168, adresses_to_scan);
    add_address_position(THIRD_OCTET, 100, adresses_to_scan);
    add_address_position_range(FOURTH_OCTET, 100, 200, adresses_to_scan);

    // select ports to scan
    struct port_store *ps_tcp_ack;
    ps_tcp_ack = malloc(sizeof(struct port_store));
    memset(ps_tcp_ack, 0, sizeof(struct port_store));
    add_port_range(22, 25, ps_tcp_ack);
    add_port(80, ps_tcp_ack);
    add_port(113, ps_tcp_ack);
    add_port(1050, ps_tcp_ack);
    add_port(35000, ps_tcp_ack);

    struct port_store *ps_tcp_syn;
    ps_tcp_syn=ps_tcp_ack;

    struct port_store *ps_udp;
    ps_udp=ps_tcp_ack;

    struct port_store *ps_icmp_echo;
    ps_icmp_echo=ps_tcp_ack;

    struct port_store *ps_scan;
    ps_scan=ps_tcp_ack;

    // initial
    char source_ip[32];
    
    struct address_store active_hosts;
    address_store_init(&active_hosts, 16);

    strcpy(source_ip, "192.168.100.182");
    int st = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (st == -1)
    {
        perror("Program only works in root");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(st, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    uint16_t port;

    int st2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    setsockopt(st2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    run_discovery(adresses_to_scan,
                  ps_tcp_ack,
                  ps_tcp_syn,
                  ps_udp,
                  ps_icmp_echo,
                  source_ip,
                  &active_hosts);

    // print up hosts
    uint32_t temp = 0;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    for (uint32_t i = 0; i < active_hosts.size; i++)
    {
        address_store_get(&active_hosts, i, &temp);
        sin.sin_addr.s_addr = temp;
        printf("Host %s up\n", inet_ntoa(sin.sin_addr));
    }

    //run scan on active hosts
    struct address_port_store results;
    ap_store_init(&results, 16);
    int pid = fork();
    if (pid == 0)
    {

        uint32_t target;
        uint16_t port;
        sleep(1);
        for (uint32_t i = 0; i < active_hosts.size; i++)
        {
            address_store_get(&active_hosts, i, &target);
            sin.sin_addr.s_addr = target;
            while (get_next_port(ps_scan, &port) == 0)
            {
                sin.sin_port = port;
                scan_tcp_syn_send(st, sin, source_ip, 80);
            }
        }
        // no idea how to time it properly here
        // sleep(0);
        exit(1);
    }
    else
    {
        scan_tcp_syn_listen(st2, &active_hosts, &results, pid);
    }

    //print results
    struct address_port_status aps_temp;
    struct sockaddr_in sin_temp;
    sin_temp.sin_family = AF_INET;
    for (uint32_t i = 0; i < results.size; i++)
    {
        ap_store_get(&results, i, &aps_temp);
        sin.sin_addr.s_addr = aps_temp.address;
        sin.sin_port = aps_temp.port;
        if (aps_temp.status == 1)
        {
            printf("Host %s, port %u open\n", inet_ntoa(sin.sin_addr), ntohs(aps_temp.port), aps_temp.status);
        }
    }
}