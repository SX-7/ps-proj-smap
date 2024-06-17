#include "smap.h"

int do_scans;
int verbose;
int main(int argc, const char **argv)
{
    do_scans = 0;
    verbose = 0;

    struct ifreq ifr;
    char source_ip[32];
    struct octet_store *adresses_to_scan;

    struct port_store *ps_tcp_ack;
    ps_tcp_ack = malloc(sizeof(struct port_store));
    memset(ps_tcp_ack, 0, sizeof(struct port_store));
    struct port_store *ps_tcp_syn;
    ps_tcp_syn = malloc(sizeof(struct port_store));
    memset(ps_tcp_syn, 0, sizeof(struct port_store));
    struct port_store *ps_udp;
    ps_udp = malloc(sizeof(struct port_store));
    memset(ps_udp, 0, sizeof(struct port_store));
    struct port_store *ps_icmp_echo;
    ps_icmp_echo = malloc(sizeof(struct port_store));
    memset(ps_icmp_echo, 0, sizeof(struct port_store));
    struct port_store *ps_scan;
    ps_scan = malloc(sizeof(struct port_store));
    memset(ps_scan, 0, sizeof(struct port_store));

    if (argc < 3)
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
        printf("Other:\n");
        printf("-v: Verbose mode\n");
        return 1;
    }
    else
    {
        const char *ifname = argv[argc - 2];

        int sd = socket(AF_PACKET, SOCK_RAW, 0);

        if (sd <= 0)
        {
            perror("socket()");
            exit(1);
        }
        if (strlen(ifname) > (IFNAMSIZ - 1))
        {
            printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
            exit(1);
        }

        strcpy(ifr.ifr_name, ifname);

        // Get interface index using name
        if (ioctl(sd, SIOCGIFADDR, &ifr) == -1)
        {
            perror("SIOCGIFADDR");
            exit(1);
        }
        if (verbose)
        {
            printf("Using source ip %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        }
        strcpy(source_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

        // select ip adresses to scan
        adresses_to_scan = malloc(sizeof(struct octet_store));
        init_address_positions(adresses_to_scan);
        parse_adresses(adresses_to_scan, argv[argc - 1]);

        char buf[255];
        for (int i = 1; i < argc - 2; i++)
        {
            if (argv[i][0] != '-')
            {
                printf("Unknown argument %s\n", argv[i]);
                exit(1);
            }
            if (!memcmp(argv[i], "-p", 2) && strlen(argv[i]) > 2)
            {
                strncpy(buf, &argv[i][2], 254);
                buf[254] = '\0';
                parse_ports(ps_scan, buf);
            }
            if (!memcmp(argv[i], "-PS", 3) && strlen(argv[i]) > 3)
            {
                strncpy(buf, &argv[i][3], 254);
                buf[254] = '\0';
                parse_ports(ps_tcp_syn, buf);
            }
            if (!memcmp(argv[i], "-PA", 3) && strlen(argv[i]) > 3)
            {
                strncpy(buf, &argv[i][3], 254);
                buf[254] = '\0';
                parse_ports(ps_tcp_ack, buf);
            }
            if (!memcmp(argv[i], "-PU", 3) && strlen(argv[i]) > 3)
            {
                strncpy(buf, &argv[i][3], 254);
                buf[254] = '\0';
                parse_ports(ps_udp, buf);
            }
            if (!memcmp(argv[i], "-PE", 3))
            {
                // adding anything to signify we're gonna be using this
                add_port(8, ps_icmp_echo);
            }
            if (!memcmp(argv[i], "-sS", 3))
            {
                do_scans = 1;
            }
            if (!memcmp(argv[i], "-v", 2))
            {
                verbose = 1;
            }
        }
    }

    // initial

    struct address_store active_hosts;
    address_store_init(&active_hosts, 16);
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

    if (!do_scans)
    {
        exit(0);
    }

    // run scan on active hosts
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
        //sleep(1);
        exit(1);
    }
    else
    {
        scan_tcp_syn_listen(st2, &active_hosts, &results, pid);
    }

    // print results
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
            printf("Host %s port %u open\n", inet_ntoa(sin.sin_addr), ntohs(aps_temp.port), aps_temp.status);
        }
    }
}