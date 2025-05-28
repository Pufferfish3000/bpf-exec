#include "config.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

union config_block g_config_block = {.canary = "According to all known laws of aviation"};

bpfexec_config_t* GetBPFExecConfig(void)
{
    bpfexec_config_t* config = &g_config_block.bpf_config;
    config->sequence_number = ntohl(config->sequence_number);
    printf("CONFIG: sequence_number = %d\n", config->sequence_number);
    return config;
}
