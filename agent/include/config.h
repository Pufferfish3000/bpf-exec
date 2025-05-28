#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct bpfexec_config
{
    uint32_t sequence_number;
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
bpfexec_config_t* get_bpfexec_config(void);

#endif /*CONFIG_H*/