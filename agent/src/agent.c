#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "networking.h"

static int CreateTCPFilterSocket();
static int CreateRawFilterSocket(struct sock_fprog* bpf);
static int AcceptPacket(int raw_sock, unsigned char** packet_data);

int StartAgent()
{
    int sock = -1;
    int exit_code = EXIT_FAILURE;
    unsigned char* packet_data = NULL;

    sock = CreateTCPFilterSocket();
    if (-1 == sock)
    {
        fprintf(stderr, "Failed to create TCP filter socket\n");
        goto end;
    }

    if (AcceptPacket(sock, &packet_data))
    {
        fprintf(stderr, "Failed to accept packet\n");
        goto end;
    }

end:
    NFREE(packet_data);
    return exit_code;
}

/**
 * @brief Accept a packet from the raw socket.
 *
 * @param raw_sock The file descriptor of the raw socket.
 * @param packet_data A double pointer to store the received packet data.
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
static int AcceptPacket(int raw_sock, unsigned char** packet_data)
{
    int exit_code = EXIT_FAILURE;
    const int recv_size = 1000;  // arbitrary size for receiving packets
    ssize_t bytes_recv = 0;
    unsigned char* raw = NULL;

    if (NULL == packet_data || NULL != *packet_data)
    {
        fprintf(stderr, "packet_data must be a NULL double pointer\n");
        goto end;
    }

    if (raw_sock < 0)
    {
        fprintf(stderr, "raw_sock must be a valid fd\n");
        goto end;
    }

    raw = calloc(recv_size, sizeof(*raw));
    if (NULL == raw)
    {
        fprintf(stderr, "Failed to calloc raw\n");
        goto clean;
    }

    // arbitrary size for receiving packets, as we only care about the data at the end
    bytes_recv = recv(raw_sock, raw, recv_size, 0);
    if (bytes_recv < 0)
    {
        perror("recv");
        fprintf(stderr, "Failed to receive data on raw_sock\n");
        goto clean;
    }

    printf("Packet received: %s\n", (char*)raw);

    *packet_data = raw;
    exit_code = EXIT_SUCCESS;
    goto end;

clean:
    NFREE(raw);

end:
    return exit_code;
}

/**
 * @brief Create a TCP filter socket for port 4578.
 * 
 * @return int the file descriptor of the created socket, or -1 on failure.
 */
static int CreateTCPFilterSocket()
{
    int sock = -1;
    const int code_size = 20;

    // generated with tcpdump -dd 'tcp port 4578'
    struct sock_filter code[] = {
        {0x28, 0, 0, 0x0000000c},  {0x15, 0, 6, 0x000086dd},   {0x30, 0, 0, 0x00000014},
        {0x15, 0, 15, 0x00000006}, {0x28, 0, 0, 0x00000036},   {0x15, 12, 0, 0x000011e2},
        {0x28, 0, 0, 0x00000038},  {0x15, 10, 11, 0x000011e2}, {0x15, 0, 10, 0x00000800},
        {0x30, 0, 0, 0x00000017},  {0x15, 0, 8, 0x00000006},   {0x28, 0, 0, 0x00000014},
        {0x45, 6, 0, 0x00001fff},  {0xb1, 0, 0, 0x0000000e},   {0x48, 0, 0, 0x0000000e},
        {0x15, 2, 0, 0x000011e2},  {0x48, 0, 0, 0x00000010},   {0x15, 0, 1, 0x000011e2},
        {0x6, 0, 0, 0x00040000},   {0x6, 0, 0, 0x00000000},
    };

    struct sock_fprog bpf = {
        .len = code_size,
        .filter = code,
    };

    sock = CreateRawFilterSocket(&bpf);
    if (-1 == sock)
    {
        fprintf(stderr, "Could not create raw filter socket\n");
    }

    return sock;
}

/**
 * @brief Create a raw filter socket with the given BPF program.
 *
 * @param bpf Pointer to the BPF program to attach to the socket.
 * @return int The file descriptor of the created socket, or -1 on failure.
 */
static int CreateRawFilterSocket(struct sock_fprog* bpf)
{
    int sock = -1;

    if (NULL == bpf)
    {
        fprintf(stderr, "bpf can not be NULL\n");
        goto end;
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (-1 == sock)
    {
        fprintf(stderr, "Could not create raw sock\n");
        goto end;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(*bpf)))
    {
        fprintf(stderr, "Could not set socket options\n");
        goto clean;
    }

    goto end;

clean:
    close(sock);
    sock = -1;
end:
    return sock;
}