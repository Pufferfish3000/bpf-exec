#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define CONFIG_PROTOCOL_TCP (1)
#define CONFIG_PROTOCOL_UDP (2)

typedef struct bpfexec_config
{
    uint32_t sequence_number;
    // uint16_t port;
    // uint8_t protocol;
} bpfexec_config_t;

union config_block
{
    bpfexec_config_t bpf_config;
    unsigned char canary[40];
};

/**
 * @brief Get the BPF execution configuration.
 * 
 * @return bpfexec_config_t* 
 */
bpfexec_config_t* GetBPFExecConfig(void);

#endif /*CONFIG_H*/