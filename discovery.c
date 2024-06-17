#include "smap.h"

int check_adress_up_tcp_syn(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    // create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_tcp_header(datagram, TEST_PACKET_SIZE, dest_sa, source_port);
    struct tcphdr *tcph = (struct tcphdr *)datagram;
    tcph->syn = 1;
    compute_ip_tcp_checksum(datagram, source_ip, dest_sa);
    // Send the packet
    if (sendto(sd, datagram, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
    {

        return -1;
    }
    // Data send successfully
    else
    {
        // attempt to receive
        struct sockaddr_in recv_sa;
        int adr_len = sizeof(struct sockaddr_in);
        if (recvfrom(sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {

            return -2;
        }
        else
        {
            struct tcphdr *tcphr = (struct tcphdr *)(datagram + sizeof(struct iphdr));
            if (memcmp(&recv_sa.sin_addr.s_addr, &dest_sa.sin_addr.s_addr, sizeof(in_addr_t)) == 0)
            {

                // got good ip
                if (tcphr->rst == 1 || (tcphr->ack == 1 & tcphr->syn == 1))
                {
                    // got good flags
                    return 0;
                }
                else
                {
                    // got corrupted flags, possibly
                    return -3;
                }
            }
            else
            {
                // bad return ip, host's probably unresponsive
                return 1;
            }
        }
    }
}

int check_adress_up_tcp_ack(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    // create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_tcp_header(datagram, TEST_PACKET_SIZE, dest_sa, source_port);
    struct tcphdr *tcph = (struct tcphdr *)datagram;
    tcph->ack = 1;
    compute_ip_tcp_checksum(datagram, source_ip, dest_sa);

    // Send the packet
    if (sendto(sd, datagram, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
    {
        return -1;
    }
    // Data send successfully
    else
    {
        // attempt to receive
        struct sockaddr_in recv_sa;
        int adr_len = sizeof(struct sockaddr_in);
        if (recvfrom(sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            return -2;
        }
        else
        {
            struct tcphdr *tcphr = (struct tcphdr *)(datagram + sizeof(struct iphdr));
            if (memcmp(&recv_sa.sin_addr.s_addr, &dest_sa.sin_addr.s_addr, sizeof(in_addr_t)) == 0)
            {
                // got good ip
                if (tcphr->rst == 1 || (tcphr->ack == 1 & tcphr->syn == 1))
                {
                    // got good flags
                    return 0;
                }
                else
                {
                    // got corrupted flags, possibly
                    return -3;
                }
            }
            else
            {
                // bad return ip, host's probably unresponsive
                return 1;
            }
        }
    }
}

int check_adress_up_udp_port_unreachable(int sd_udp, int sd_icmp, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    // create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_udp_header(datagram, TEST_PACKET_SIZE, dest_sa, source_port);
    //*somehow* wrong checksum. doesn't matter, since it's not mandatory for ipv4
    compute_ip_udp_checksum(datagram, source_ip, dest_sa);
    // simultaneous send/receive
    if (fork() == 0)
    {
        struct sockaddr_in recv_sa;
        int adr_len = sizeof(struct sockaddr_in);

        if (recvfrom(sd_icmp, datagram, sizeof(struct icmphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            exit(-2);
        }
        else
        {
            struct icmphdr *icmphr = (struct icmphdr *)(datagram + sizeof(struct iphdr));
            if (memcmp(&recv_sa.sin_addr.s_addr, &dest_sa.sin_addr.s_addr, sizeof(in_addr_t)) == 0)
            {

                // got response, check it it's correct
                if (icmphr->type == ICMP_UNREACH & icmphr->code == ICMP_PORT_UNREACH)
                {
                    exit(0);
                }
                else
                {
                    exit(1);
                }
            }
            else
            {
                exit(2);
            }
        }
        exit(-3);
    }
    else
    {
        // Send the packet
        if (sendto(sd_udp, datagram, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
        {
            return -1;
        }
        int c_ret;

        wait(&c_ret);
        return (c_ret);
    }
}

int check_adress_up_icmp_echo(int sd_sender, int sd_listener, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    // create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_icmp_header(datagram, TEST_PACKET_SIZE);
    struct icmphdr *icmph = (struct icmphdr *)datagram;
    icmph->type = ICMP_ECHO;
    icmph->un.echo.id = htons(17213);
    // icmph->code should be 0 according to docs
    compute_ip_icmp_checksum(datagram, source_ip, dest_sa);

    // simultaneous send/receive
    if (fork() == 0)
    {
        struct sockaddr_in recv_sa;
        int adr_len = sizeof(struct sockaddr_in);

        if (recvfrom(sd_listener, datagram, sizeof(struct icmphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            exit(-2);
        }
        else
        {
            struct icmphdr *icmphr = (struct icmphdr *)(datagram + sizeof(struct iphdr));
            if (memcmp(&recv_sa.sin_addr.s_addr, &dest_sa.sin_addr.s_addr, sizeof(in_addr_t)) == 0)
            {
                // got response, check it it's correct
                if (icmphr->type == ICMP_ECHOREPLY)
                {
                    exit(0);
                }
                else
                {
                    exit(1);
                }
            }
            else
            {
                exit(2);
            }
        }
        exit(-3);
    }
    else
    {
        // Send the packet
        if (sendto(sd_sender, datagram, sizeof(struct icmphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
        {
            return -1;
        }
        int c_ret;
        wait(&c_ret);
        return (c_ret);
    }
}

int run_discovery(struct octet_store *adresses_to_scan,
                  struct port_store *ps_tcp_ack,
                  struct port_store *ps_tcp_syn,
                  struct port_store *ps_udp,
                  struct port_store *ps_icmp_echo,
                  char *source_ip,
                  struct address_store *active_hosts)
{
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
    int st = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (st == -1)
    {
        perror("Program only works in root");
        exit(-1);
    }

    // timeout for socketss
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(st, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    uint16_t port;

    int su = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int si = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    setsockopt(si, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(su, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    int si2 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    setsockopt(si2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    int cont_flag = 0;
    while (sin.sin_addr.s_addr != -1)
    {
        if (verbose)
        {
            printf("Discovery on %s\n", inet_ntoa(sin.sin_addr));
        }
        // tcp syn
        while (get_next_port(ps_tcp_syn, &port) == 0)
        {
            sin.sin_port = port;
            if (check_adress_up_tcp_syn(st, sin, source_ip, 80) == 0)
            {
                address_store_add_if_nexists(active_hosts, sin.sin_addr.s_addr);
                cont_flag = 1;
                // printf("Syn: %s port %u up\n",inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
            }
            if (cont_flag)
            {
                break;
            }
        }
        if (cont_flag)
        {
            cont_flag = 0;
            sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
            continue;
        }
        // tcp ack
        while (get_next_port(ps_tcp_ack, &port) == 0)
        {
            sin.sin_port = port;
            if (check_adress_up_tcp_ack(st, sin, source_ip, 80) == 0)
            {
                address_store_add_if_nexists(active_hosts, sin.sin_addr.s_addr);
                cont_flag = 1;
                /// printf("Ack: %s port %u up\n",inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
            }
            if (cont_flag)
            {
                break;
            }
        }
        if (cont_flag)
        {
            cont_flag = 0;
            sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
            continue;
        }
        // udp
        while (get_next_port(ps_udp, &port) == 0)
        {
            sin.sin_port = port;
            if (check_adress_up_udp_port_unreachable(su, si, sin, source_ip, 80) == 0)
            {
                address_store_add_if_nexists(active_hosts, sin.sin_addr.s_addr);
                cont_flag = 1;
                // printf("UDP: %s port %u up\n",inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
            }
            if (cont_flag)
            {
                break;
            }
        }
        if (cont_flag)
        {
            cont_flag = 0;
            sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
            continue;
        }
        // icmp
        while (get_next_port(ps_icmp_echo, &port) == 0)
        {
            // actually doesn't care abt ports
            sin.sin_port = port;
            if (check_adress_up_icmp_echo(si, si2, sin, source_ip, 80) == 0)
            {
                address_store_add_if_nexists(active_hosts, sin.sin_addr.s_addr);
                cont_flag = 1;
                // printf("ICMP: %s port %u up\n",inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
            }
            if (cont_flag)
            {
                break;
            }
        }
        if (cont_flag)
        {
            cont_flag = 0;
            sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
            continue;
        }
        sin.sin_addr.s_addr = get_next_address(adresses_to_scan);
    }
}