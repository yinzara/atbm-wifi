/*
 * CLI Stubs - No-op implementations for Improv WiFi mode
 *
 * The Improv WiFi implementation doesn't use AT commands or CLI,
 * so these are stub implementations.
 */

#include <stdio.h>
#include "atbm_debug.h"

/* Global variable stubs */
int lib_ble_reduce_mem = 0;

void cli_init(void)
{
    iot_printf("[CLI] Improv WiFi mode - AT commands disabled\n");
}

void cli_free(void)
{
    /* Nothing to free */
}

void atcmd_init_ble(void)
{
    iot_printf("[CLI] Improv WiFi mode - AT commands disabled\n");
}

void cli_set_event(const char *cmd_line, int len)
{
    /* No-op - CLI events not used in Improv WiFi mode */
    (void)cmd_line;
    (void)len;
}

void ble_startup_indication(const void *data)
{
    /* No-op - startup indication not used in Improv WiFi mode */
    (void)data;
}
