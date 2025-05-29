#include "config.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

union config_block g_config_block = {.canary = CANARY_VALUE};

bpfexec_config_t* GetBPFExecConfig(void)
{
    bpfexec_config_t* config = &g_config_block.bpf_config;
    config->sequence_number = ntohl(config->sequence_number);
    config->port = ntohs(config->port);

    printf("CONFIG: sequence_number = %u\n", config->sequence_number);
    printf("CONFIG: port = %u\n", config->port);
    printf("CONFIG: protocol = %u\n", config->protocol);
    return config;
}
