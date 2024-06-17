#include "smap.h"
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

int setup_ip_tcp_header(char *datagram, size_t datagram_max_len, struct sockaddr_in sa, int source_port)
{
    // ensure it's empty
    memset(datagram, 0, datagram_max_len);
    // TCP Header defult setup
    struct tcphdr *tcph = (struct tcphdr *)datagram;
    tcph->source = htons(source_port);
    tcph->dest = sa.sin_port;
    tcph->doff = 5;                         // tcp header size, 5 is for minimal (our current)
    tcph->window = htons(TEST_PACKET_SIZE); /* maximum allowed window size */
}

int setup_ip_udp_header(char *datagram, size_t datagram_max_len, struct sockaddr_in sa, int source_port)
{
    // ensure it's empty
    memset(datagram, 0, datagram_max_len);
    // TCP Header defult setup
    struct udphdr *udph = (struct udphdr *)datagram;
    udph->source = htons(source_port);
    udph->dest = sa.sin_port;
    udph->len = htons(8); // udp header size, 8 is for minimal (our current)
}

int compute_ip_tcp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa)
{
    // create pseudo IP header for checksum, fill it with data
    struct pseudo_header psh;
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sa.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));
    // Now the TCP checksum, simulate ip+tcp header and use csum on it
    char *pseudogram;
    struct tcphdr *tcph = (struct tcphdr *)datagram;
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

int compute_ip_udp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa)
{
    // create pseudo IP header for checksum, fill it with data
    struct pseudo_header psh;
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sa.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.length = htons(sizeof(struct udphdr));
    // Now the UDP checksum, simulate ip+udp header and use csum on it
    char *pseudogram;
    struct udphdr *udph = (struct udphdr *)datagram;
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));

    udph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

int setup_ip_icmp_header(char *datagram, size_t datagram_max_len)
{
    // we actually don't need to do anything else here
    memset(datagram, 0, datagram_max_len);
}

int compute_ip_icmp_checksum(char *datagram, char *source_ip, struct sockaddr_in sa)
{
    // icmp checksum only needs the icmp header
    //  Now the checksum, simulate ip+icmp header and use csum on it
    char *pseudogram;
    struct icmphdr *icmph = (struct icmphdr *)datagram;
    int psize = sizeof(struct icmphdr);
    pseudogram = malloc(psize);

    memcpy(pseudogram, icmph, sizeof(struct icmphdr));

    icmph->checksum = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);
}

int init_address_positions(struct octet_store *oc)
{
    memset(oc->octet.first, 0, sizeof(uint16_t) * 256);
    memset(oc->octet.second, 0, sizeof(uint16_t) * 256);
    memset(oc->octet.third, 0, sizeof(uint16_t) * 256);
    memset(oc->octet.fourth, 0, sizeof(uint16_t) * 256);
    oc->count.first = 0;
    oc->count.second = 0;
    oc->count.third = 0;
    oc->count.fourth = 0;
    oc->offset.first = 0;
    oc->offset.second = 0;
    oc->offset.third = 0;
    oc->offset.fourth = 0;
}

int add_address_position(int octet, short address, struct octet_store *oc)
{
    if (address < 0 || address > 255)
    {
        return -1;
    }
    if (octet == FIRST_OCTET)
    {
        for (size_t i = 0; i < oc->count.first; i++)
        {
            if (oc->octet.first[i] == address)
            {
                return -2;
            }
        }
        oc->octet.first[oc->count.first] = address;
        oc->count.first++;
    }
    if (octet == SECOND_OCTET)
    {
        for (size_t i = 0; i < oc->count.second; i++)
        {
            if (oc->octet.second[i] == address)
            {
                return -2;
            }
        }
        oc->octet.second[oc->count.second] = address;
        oc->count.second++;
    }
    if (octet == THIRD_OCTET)
    {
        for (size_t i = 0; i < oc->count.third; i++)
        {
            if (oc->octet.third[i] == address)
            {
                return -2;
            }
        }
        oc->octet.third[oc->count.third] = address;
        oc->count.third++;
    }
    if (octet == FOURTH_OCTET)
    {
        for (size_t i = 0; i < oc->count.fourth; i++)
        {
            if (oc->octet.fourth[i] == address)
            {
                return -2;
            }
        }
        oc->octet.fourth[oc->count.fourth] = address;
        oc->count.fourth++;
    }
    return 0;
}

int add_address_position_range(int octet, short address_bottom, short address_top_inclusive, struct octet_store *oc)
{
    if (address_bottom < 0 || address_bottom > 255 || address_top_inclusive < 0 || address_top_inclusive > 255)
    {
        return -1;
    }
    for (short i = address_bottom; i <= address_top_inclusive; i++)
    {
        add_address_position(octet, i, oc);
    }
}

in_addr_t get_next_address(struct octet_store *oc)
{
    char buf[100];
    if (oc->offset.first == oc->count.first)
    {
        oc->offset.first = 0;
        return -1;
    }
    snprintf(buf, 100, "%d.%d.%d.%d", oc->octet.first[oc->offset.first], oc->octet.second[oc->offset.second], oc->octet.third[oc->offset.third], oc->octet.fourth[oc->offset.fourth]);
    oc->offset.fourth++;
    if (oc->offset.fourth == oc->count.fourth)
    {
        oc->offset.fourth = 0;
        oc->offset.third++;
    }
    if (oc->offset.third == oc->count.third)
    {
        oc->offset.third = 0;
        oc->offset.second++;
    }
    if (oc->offset.second == oc->count.second)
    {
        oc->offset.second = 0;
        oc->offset.first++;
    }
    return inet_addr(buf);
}

int check_if_in_store(in_addr_t address, struct octet_store *oc)
{
    char buf[100];
    in_addr_t temp;
    for (uint32_t first = 0; first < oc->count.first; first++)
    {
        for (uint32_t second = 0; second < oc->count.second; second++)
        {
            for (uint32_t third = 0; third < oc->count.third; third++)
            {
                for (uint32_t fourth = 0; fourth < oc->count.fourth; fourth++)
                {
                    snprintf(buf, 100, "%d.%d.%d.%d", oc->octet.first[first], oc->octet.second[second], oc->octet.third[third], oc->octet.fourth[fourth]);
                    temp =inet_addr(buf);
                    if(memcmp(&temp,&address,sizeof(in_addr_t))==0){
                        return 0;
                        
                    };
                }
            }
        }
    }
    return 1;
}

uint16_t add_port(uint16_t port_index, struct port_store *ps)
{
    switch (port_index % 8)
    {
    case 0:
        ps->chunk[port_index / 8].p0 = 1;
        break;
    case 1:
        ps->chunk[port_index / 8].p1 = 1;
        break;
    case 2:
        ps->chunk[port_index / 8].p2 = 1;
        break;
    case 3:
        ps->chunk[port_index / 8].p3 = 1;
        break;
    case 4:
        ps->chunk[port_index / 8].p4 = 1;
        break;
    case 5:
        ps->chunk[port_index / 8].p5 = 1;
        break;
    case 6:
        ps->chunk[port_index / 8].p6 = 1;
        break;
    case 7:
        ps->chunk[port_index / 8].p7 = 1;
        break;
    default:
        return -1;
        break;
    }
    return 0;
}

uint16_t remove_port(uint16_t port_index, struct port_store *ps)
{
    switch (port_index % 8)
    {
    case 0:
        ps->chunk[port_index / 8].p0 = 0;
        break;
    case 1:
        ps->chunk[port_index / 8].p1 = 0;
        break;
    case 2:
        ps->chunk[port_index / 8].p2 = 0;
        break;
    case 3:
        ps->chunk[port_index / 8].p3 = 0;
        break;
    case 4:
        ps->chunk[port_index / 8].p4 = 0;
        break;
    case 5:
        ps->chunk[port_index / 8].p5 = 0;
        break;
    case 6:
        ps->chunk[port_index / 8].p6 = 0;
        break;
    case 7:
        ps->chunk[port_index / 8].p7 = 0;
        break;
    default:
        return -1;
        break;
    }
    return 0;
}

u_int16_t get_port(uint16_t port_index, struct port_store *ps)
{
    switch (port_index % 8)
    {
    case 0:
        return ps->chunk[port_index / 8].p0;
        break;
    case 1:
        return ps->chunk[port_index / 8].p1;
        break;
    case 2:
        return ps->chunk[port_index / 8].p2;
        break;
    case 3:
        return ps->chunk[port_index / 8].p3;
        break;
    case 4:
        return ps->chunk[port_index / 8].p4;
        break;
    case 5:
        return ps->chunk[port_index / 8].p5;
        break;
    case 6:
        return ps->chunk[port_index / 8].p6;
        break;
    case 7:
        return ps->chunk[port_index / 8].p7;
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

u_int16_t add_port_range(uint16_t start_port, uint16_t end_port_inclusive, struct port_store *ps)
{
    for (uint16_t i = start_port; i <= end_port_inclusive; i++)
    {
        add_port(i, ps);
    }
}

u_int16_t remove_port_range(uint16_t start_port, uint16_t end_port_inclusive, struct port_store *ps)
{
    for (uint16_t i = start_port; i <= end_port_inclusive; i++)
    {
        remove_port(i, ps);
    }
}

uint16_t get_next_port(struct port_store *ps, uint16_t *port)
{
    // when started right at the end
    if (ps->offset > UINT16_MAX)
    {
        ps->offset = 0;
        return -1;
    }

    while (ps->offset <= UINT16_MAX)
    {
        if (get_port(ps->offset, ps) == 1)
        {
            *port = htons(ps->offset);
            ps->offset++;
            return 0;
        }
        ps->offset++;
    }
    // finished iterating
    ps->offset = 0;
    return -1;
}

int address_store_init(struct address_store *as, uint32_t init_capacity)
{
    as->capacity = init_capacity;
    as->size = 0;
    as->addresses = malloc(as->capacity * sizeof(uint32_t));
    memset(as->addresses, 0, as->capacity * sizeof(uint32_t));
    return 0;
}

int address_store_get(struct address_store *as, uint32_t index, uint32_t *dest)
{
    if (index < as->size)
    {
        *dest = as->addresses[index];
        return 0;
    }
    else
    {
        return -1;
    }
}

int address_store_add(struct address_store *as, uint32_t data)
{
    if (as->size < as->capacity)
    {
        as->addresses[as->size] = data;
        as->size++;
    }
    else
    {
        uint32_t *new_pointer = realloc(as->addresses, as->capacity * sizeof(uint32_t) * 2);
        as->addresses = new_pointer;
        as->capacity *= 2;
        as->addresses[as->size] = data;
        as->size++;
    }
}

int address_store_add_if_nexists(struct address_store *as, uint32_t data)
{
    // naive approach cuz lazy
    uint32_t temp = 0;
    for (uint32_t i = 0; i < as->size; i++)
    {
        address_store_get(as, i, &temp);
        if (memcmp(&data, &temp, sizeof(uint32_t)) == 0)
        {
            return -1;
        }
    }
    address_store_add(as, data);
    return 0;
}

int address_store_check_if_exists(struct address_store *as, uint32_t data)
{
    // naive approach cuz lazy
    uint32_t temp = 0;
    for (uint32_t i = 0; i < as->size; i++)
    {
        address_store_get(as, i, &temp);
        if (memcmp(&data, &temp, sizeof(uint32_t)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

int ap_store_init(struct address_port_store *as, uint32_t init_capacity)
{
    as->capacity = init_capacity;
    as->size = 0;
    as->addresses = malloc(as->capacity * sizeof(struct address_port_status));
    memset(as->addresses, 0, as->capacity * sizeof(struct address_port_status));
    return 0;
}

int ap_store_get(struct address_port_store *as, uint32_t index, struct address_port_status *ap)
{
    if (index < as->size)
    {
        *ap = as->addresses[index];
        return 0;
    }
    else
    {
        return -1;
    }
}

int ap_store_add(struct address_port_store *as, struct address_port_status ap)
{
    if (as->size < as->capacity)
    {
        as->addresses[as->size] = ap;
        as->size++;
    }
    else
    {
        struct address_port_status *new_pointer = realloc(as->addresses, as->capacity * sizeof(struct address_port_status) * 2);
        as->addresses = new_pointer;
        as->capacity *= 2;
        as->addresses[as->size] = ap;
        as->size++;
    }
}

int ap_store_add_if_nexists(struct address_port_store *as, struct address_port_status ap)
{
    // naive approach cuz lazy
    struct address_port_status temp;
    for (uint32_t i = 0; i < as->size; i++)
    {
        ap_store_get(as, i, &temp);
        // we don't wanna duplicate ports, even if diff statuses
        if (memcmp(&ap, &temp, sizeof(uint32_t) + sizeof(uint16_t)) == 0)
        {
            return -1;
        }
    }
    ap_store_add(as, ap);
}

int ap_store_check_if_exists(struct address_port_store *as, struct address_port_status ap)
{
    struct address_port_status temp;
    for (uint32_t i = 0; i < as->size; i++)
    {
        ap_store_get(as, i, &temp);
        if (memcmp(&ap, &temp, sizeof(uint32_t) + sizeof(uint16_t)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

int parse_adresses(struct octet_store *os, const char *in_address)
{
    int i = 0;
    int current_octet = FIRST_OCTET;
    int first_buf = 0;
    int second_buf = 0;
    int in_range = 0;
    while (in_address[i] != '\0')
    {
        if (current_octet == 4)
        {
            printf("Wrong octet count %u\n", current_octet + 1);
        }
        if (isdigit(in_address[i]))
        {
            if (in_range)
            {
                second_buf += in_address[i] - (long)'0';
                verify_address(second_buf);
                second_buf *= 10;
            }
            else
            {
                first_buf += in_address[i] - (long)'0';
                verify_address(first_buf);
                first_buf *= 10;
            }
        }
        else
        {
            switch (in_address[i])
            {
            case '.':
                if (in_range)
                {
                    add_address_position_range(current_octet, first_buf / 10, second_buf / 10, os);
                }
                else
                {
                    add_address_position(current_octet, first_buf / 10, os);
                }
                first_buf = 0;
                second_buf = 0;
                in_range = 0;
                current_octet += 1;
                break;
            case ',':
                if (in_range)
                {
                    add_address_position_range(current_octet, first_buf / 10, second_buf / 10, os);
                }
                else
                {
                    add_address_position(current_octet, first_buf / 10, os);
                }
                first_buf = 0;
                second_buf = 0;
                in_range = 0;
                break;
            case '-':
                if (in_range)
                {
                    printf("Multipoint address range\n");
                }
                else
                {
                    in_range = 1;
                }
                break;
            default:
                break;
            }
        }
        i++;
    }
    if (in_range)
    {
        add_address_position_range(current_octet, first_buf / 10, second_buf / 10, os);
    }
    else
    {
        add_address_position(current_octet, first_buf / 10, os);
    }
}

int verify_address(int address)
{
    if (address > 255 || address < 0)
    {
        printf("Wrong address range %d\n", address);
        exit(1);
    }
}

int parse_ports(struct port_store *ps, const char *in_ports)
{
    int i = 0;
    int first_buf = 0;
    int second_buf = 0;
    int in_range = 0;
    while (in_ports[i] != '\0')
    {
        if (isdigit(in_ports[i]))
        {
            if (in_range)
            {
                second_buf += in_ports[i] - (long)'0';
                verify_port(second_buf);
                second_buf *= 10;
            }
            else
            {
                first_buf += in_ports[i] - (long)'0';
                verify_port(first_buf);
                first_buf *= 10;
            }
        }
        else
        {
            switch (in_ports[i])
            {
            case '.':
                if (in_range)
                {
                    add_port_range(first_buf / 10, second_buf / 10, ps);
                }
                else
                {
                    add_port(first_buf / 10, ps);
                }
                first_buf = 0;
                second_buf = 0;
                in_range = 0;
                break;
            case ',':
                if (in_range)
                {
                    add_port_range(first_buf / 10, second_buf / 10, ps);
                }
                else
                {
                    add_port(first_buf / 10, ps);
                }
                first_buf = 0;
                second_buf = 0;
                in_range = 0;
                break;
            case '-':
                if (in_range)
                {
                    printf("Multipoint address range\n");
                }
                else
                {
                    in_range = 1;
                }
                break;
            default:
                break;
            }
        }
        i++;
    }
    if (in_range)
    {
        add_port_range(first_buf / 10, second_buf / 10, ps);
    }
    else
    {
        add_port(first_buf / 10, ps);
    }
}

int verify_port(int port)
{
    if (port > UINT16_MAX || port < 0)
    {
        printf("Wrong port range %d\n", port);
        exit(1);
    }
}