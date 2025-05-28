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

int CreateRawFilterSocket(struct sock_fprog* bpf)
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

int AcceptPacket(int raw_sock, unsigned char** packet_data)
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