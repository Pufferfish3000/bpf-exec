#ifndef NETWORKING_H
#define NETWORKING_H

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