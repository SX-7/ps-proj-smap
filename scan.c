#include "smap.h"

int scan_tcp_syn_send(int sd, struct sockaddr_in dest_sa, char *source_ip, int source_port)
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

int scan_tcp_syn_listen(int sd, struct address_store *as, struct address_port_store *aps, int sender_pid)
{
    // attempt to receive
    char datagram[TEST_PACKET_SIZE];
    memset(datagram, 0, TEST_PACKET_SIZE);
    struct sockaddr_in recv_sa;
    socklen_t adr_len = sizeof(struct sockaddr_in);
    int status =0;
    while (1)
    {
        
        //checkup on child
        int pid = waitpid(sender_pid, &status, WNOHANG);
        if(status!=0){
            return 0;
        }

        if (recvfrom(sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), 0, (struct sockaddr *)&recv_sa, &adr_len) < 0)
        {
            perror("recvfrom error");
        }
        else
        {
            struct tcphdr *tcphr = (struct tcphdr *)(datagram + sizeof(struct iphdr));
            if(address_store_check_if_exists(as,recv_sa.sin_addr.s_addr)==0){
                //existing ip
                // got good ip
                if (tcphr->ack == 1 && tcphr->syn == 1)
                {
                    struct address_port_status ap;
                    ap.address=recv_sa.sin_addr.s_addr;
                    ap.port=tcphr->source;
                    ap.status=1;
                    if(ap_store_add_if_nexists(aps,ap)==0){
                        printf("%s, %u, %u\n", inet_ntoa(recv_sa.sin_addr),tcphr->source,ap.status);
                    }
                    // got good flags
                    continue;
                }
                if (tcphr->rst == 1)
                {
                    struct address_port_status ap;
                    ap.address=recv_sa.sin_addr.s_addr;
                    ap.port=tcphr->source;
                    ap.status=0;
                    if(ap_store_add_if_nexists(aps,ap)==0){
                        printf("%s, %u, %u\n", inet_ntoa(recv_sa.sin_addr),tcphr->source,ap.status);
                    }
                    //port closed
                    continue;
                }
                else
                {
                    //unexpected, ignore
                }

            }
            else
            {
                // bad return ip, ignore
            }
        }
    }
}
