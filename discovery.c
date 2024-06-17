#include "smap.h"

int check_adress_up_tcp_syn(struct octet_store *os, struct port_store *ps_tcp_syn, char *source_ip, int source_port, struct address_store *results)
{

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = get_next_address(os);
    int cont_flag = 0;
    int st = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    int st2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(st, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(st2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    int pid = fork();

    if (pid == 0)
    {
        uint32_t target;
        uint16_t port;
        //sleep(1);
        while (sin.sin_addr.s_addr != -1)
        {

            while (get_next_port(ps_tcp_syn, &port) == 0)
            {
                sin.sin_port = port;
                check_adress_up_tcp_syn_send(st, sin, source_ip, 80);
            }
            sin.sin_addr.s_addr = get_next_address(os);
        }
        // no idea how to time it properly here
        //sleep(1);
        exit(1);
    }
    else
    {

        check_adress_up_tcp_syn_listen(st2, os, results, pid);
    }
    close(st);
    close(st2);
}

int check_adress_up_tcp_syn_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
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
        return 0;
    }
}

int check_adress_up_tcp_syn_listen(int sd, struct octet_store *os, struct address_store *as, int sender_pid)
{
    // attempt to receive
    char datagram[TEST_PACKET_SIZE];
    memset(datagram, 0, TEST_PACKET_SIZE);
    struct sockaddr_in recv_sa;
    socklen_t adr_len = sizeof(struct sockaddr_in);
    int status = 0;
    int flags = 0;
    while (1)
    {

        // checkup on child
        int pid = waitpid(sender_pid, &status, WNOHANG);
        if (status != 0)
        {
            // if sender finished the work, parse the rest of the buffer and quit
            flags |= MSG_DONTWAIT;
        }

        if (recvfrom(sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), flags, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            perror("recvfrom error");
        }
        else
        {
            struct tcphdr *tcphr = (struct tcphdr *)(datagram + sizeof(struct iphdr));
            if (check_if_in_store(recv_sa.sin_addr.s_addr, os) == 0)
            {
                // existing ip
                //  got good ip
                if (address_store_add_if_nexists(as, recv_sa.sin_addr.s_addr) == 0)
                {
                    // no packet data checks, anything signifies the host is up
                    if(verbose){printf("TCP SYN: Host %s up\n", inet_ntoa(recv_sa.sin_addr));}
                }
            }
            else
            {
                // bad return ip, ignore
            }
        }
    }
}

int check_adress_up_tcp_ack(struct octet_store *os, struct port_store *ps_tcp_ack, char *source_ip, int source_port, struct address_store *results)
{

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = get_next_address(os);
    int cont_flag = 0;
    int st = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    int st2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(st, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(st2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    int pid = fork();

    if (pid == 0)
    {
        uint32_t target;
        uint16_t port;
        //sleep(1);
        while (sin.sin_addr.s_addr != -1)
        {

            while (get_next_port(ps_tcp_ack, &port) == 0)
            {
                sin.sin_port = port;
                check_adress_up_tcp_ack_send(st, sin, source_ip, 80);
            }
            sin.sin_addr.s_addr = get_next_address(os);
        }
        // no idea how to time it properly here
        //sleep(1);
        exit(1);
    }
    else
    {

        check_adress_up_tcp_ack_listen(st2, os, results, pid);
    }
    close(st);
    close(st2);
}

int check_adress_up_tcp_ack_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
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
        return 0;
    }
}

int check_adress_up_tcp_ack_listen(int sd, struct octet_store *os, struct address_store *as, int sender_pid)
{
    // attempt to receive
    char datagram[TEST_PACKET_SIZE];
    memset(datagram, 0, TEST_PACKET_SIZE);
    struct sockaddr_in recv_sa;
    socklen_t adr_len = sizeof(struct sockaddr_in);
    int status = 0;
    int flags = 0;
    while (1)
    {

        // checkup on child
        int pid = waitpid(sender_pid, &status, WNOHANG);
        if (status != 0)
        {
            // if sender finished the work, parse the rest of the buffer and quit
            flags |= MSG_DONTWAIT;
        }

        if (recvfrom(sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), flags, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            perror("recvfrom error");
        }
        else
        {
            struct tcphdr *tcphr = (struct tcphdr *)(datagram + sizeof(struct iphdr));
            if (check_if_in_store(recv_sa.sin_addr.s_addr, os) == 0)
            {
                // existing ip
                //  got good ip
                if (address_store_add_if_nexists(as, recv_sa.sin_addr.s_addr) == 0)
                {
                    // no packet data checks, anything signifies the host is up
                    if(verbose){printf("TCP ACK: Host %s up\n", inet_ntoa(recv_sa.sin_addr));}
                }
            }
            else
            {
                // bad return ip, ignore
            }
        }
    }
}

int check_adress_up_udp_port_unreachable(struct octet_store *os, struct port_store *ps_udp, char *source_ip, int source_port, struct address_store *results)
{

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = get_next_address(os);
    int cont_flag = 0;
    int su = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    int si = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(su, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(si, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    int pid = fork();

    if (pid == 0)
    {
        uint32_t target;
        uint16_t port;
        //sleep(1);
        while (sin.sin_addr.s_addr != -1)
        {

            while (get_next_port(ps_udp, &port) == 0)
            {
                sin.sin_port = port;
                check_adress_up_udp_port_unreachable_send(su, sin, source_ip, 80);
            }
            sin.sin_addr.s_addr = get_next_address(os);
        }
        // no idea how to time it properly here
        //sleep(1);
        exit(1);
    }
    else
    {

        check_adress_up_udp_port_unreachable_listen(si, os, results, pid);
    }
    close(su);
    close(si);
}

int check_adress_up_udp_port_unreachable_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    // create dgram
    // create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_udp_header(datagram, TEST_PACKET_SIZE, dest_sa, source_port);
    //*somehow* wrong checksum. doesn't matter, since it's not mandatory for ipv4
    compute_ip_udp_checksum(datagram, source_ip, dest_sa);
    // simultaneous send/receive

    // Send the packet
    if (sendto(sd, datagram, sizeof(struct udphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
    {
        return -1;
    }
    // Data send successfully
    else
    {
        return 0;
    }
}

int check_adress_up_udp_port_unreachable_listen(int sd, struct octet_store *os, struct address_store *as, int sender_pid)
{
    // attempt to receive
    char datagram[TEST_PACKET_SIZE];
    memset(datagram, 0, TEST_PACKET_SIZE);
    struct sockaddr_in recv_sa;
    socklen_t adr_len = sizeof(struct sockaddr_in);
    int status = 0;
    int flags = 0;
    while (1)
    {
        // checkup on child
        int pid = waitpid(sender_pid, &status, WNOHANG);
        if (status != 0)
        {
            // if sender finished the work, parse the rest of the buffer and quit
            flags |= MSG_DONTWAIT;
        }
        if (recvfrom(sd, datagram, sizeof(struct icmphdr) + sizeof(struct iphdr), flags, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            perror("recvfrom error");
        }
        else
        {
            struct icmphdr *icmphr = (struct icmphdr *)(datagram + sizeof(struct iphdr));
            if(check_if_in_store(recv_sa.sin_addr.s_addr, os) == 0)
            {
                // got response, check it it's correct
                if (icmphr->type == ICMP_UNREACH & icmphr->code == ICMP_PORT_UNREACH)
                {
                    // no packet data checks, anything signifies the host is up
                    if (address_store_add_if_nexists(as, recv_sa.sin_addr.s_addr) == 0)
                    {

                        if(verbose){printf("UDP: Host %s up\n", inet_ntoa(recv_sa.sin_addr));}
                    }
                }
            }
        }
    }
}

int check_adress_up_icmp_echo(struct octet_store *os, struct port_store *ps_udp, char *source_ip, int source_port, struct address_store *results)
{

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = get_next_address(os);
    int cont_flag = 0;
    int su = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    int si = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(su, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(si, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    int pid = fork();

    if (pid == 0)
    {
        uint32_t target;
        uint16_t port;
        //sleep(1);
        while (sin.sin_addr.s_addr != -1)
        {

            while (get_next_port(ps_udp, &port) == 0)
            {
                sin.sin_port = port;
                check_adress_up_icmp_echo_send(su, sin, source_ip, 80);
            }
            sin.sin_addr.s_addr = get_next_address(os);
        }
        // no idea how to time it properly here
        //sleep(1);
        exit(1);
    }
    else
    {

        check_adress_up_icmp_echo_listen(si, os, results, pid);
    }
    close(su);
    close(si);
}

int check_adress_up_icmp_echo_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
{
    /// create dgram
    char datagram[TEST_PACKET_SIZE];
    setup_ip_icmp_header(datagram, TEST_PACKET_SIZE);
    struct icmphdr *icmph = (struct icmphdr *)datagram;
    icmph->type = ICMP_ECHO;
    icmph->un.echo.id = htons(17213);
    // icmph->code should be 0 according to docs
    compute_ip_icmp_checksum(datagram, source_ip, dest_sa);

    // Send the packet
    if (sendto(sd, datagram, sizeof(struct icmphdr), 0, (struct sockaddr *)&dest_sa, sizeof(dest_sa)) < 0)
    {
        return -1;
    }
    // Data send successfully
    else
    {
        return 0;
    }
}

int check_adress_up_icmp_echo_listen(int sd, struct octet_store *os, struct address_store *as, int sender_pid)
{
    // attempt to receive
    char datagram[TEST_PACKET_SIZE];
    memset(datagram, 0, TEST_PACKET_SIZE);
    struct sockaddr_in recv_sa;
    socklen_t adr_len = sizeof(struct sockaddr_in);
    int status = 0;
    int flags = 0;
    while (1)
    {
        // checkup on child
        int pid = waitpid(sender_pid, &status, WNOHANG);
        if (status != 0)
        {
            // if sender finished the work, parse the rest of the buffer and quit
            flags |= MSG_DONTWAIT;
        }
        if (recvfrom(sd, datagram, sizeof(struct icmphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            perror("recvfrom error");
        }
        else
        {
            struct icmphdr *icmphr = (struct icmphdr *)(datagram + sizeof(struct iphdr));
            if(check_if_in_store(recv_sa.sin_addr.s_addr, os) == 0)
            {
                // got response, check it it's correct
                //if (icmphr->type == ICMP_ECHOREPLY)
                //{
                    // no packet data checks, anything signifies the host is up
                    if (address_store_add_if_nexists(as, recv_sa.sin_addr.s_addr) == 0)
                    {

                        if(verbose){printf("ICMP: Host %s up\n", inet_ntoa(recv_sa.sin_addr));}
                    }
                //}
            }
        }
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
    check_adress_up_tcp_syn(adresses_to_scan, ps_tcp_syn, source_ip, 80, active_hosts);
    check_adress_up_tcp_ack(adresses_to_scan, ps_tcp_ack, source_ip, 80, active_hosts);
    check_adress_up_udp_port_unreachable(adresses_to_scan, ps_udp, source_ip, 80, active_hosts);
    check_adress_up_icmp_echo(adresses_to_scan, ps_icmp_echo, source_ip, 80, active_hosts);
}