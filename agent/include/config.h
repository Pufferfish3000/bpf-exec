#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_PROTOCOL_TCP (0xff)
#define CONFIG_PROTOCOL_UDP (0xfe)

#define CANARY_VALUE \
    {0x41, 0x39, 0x31, 0x54, 0x21, 0xff, 0x3d, 0xc1, 0x7a, 0x45, 0x1b, 0x4e, 0x31, 0x5d, 0x36, 0xc1}

typedef struct __attribute__((packed)) bpfexec_config
{
    uint8_t protocol;
    uint16_t port;
    uint32_t sequence_number;
} bpfexec_config_t;

union config_block
{
    bpfexec_config_t bpf_config;
    unsigned char canary[16];
};

/**
 * @brief Get the BPF execution configuration.
 * 
 * @return bpfexec_config_t* 
 */
bpfexec_config_t* GetBPFExecConfig(void);

#endif /*CONFIG_H*/