/*
 * Improv WiFi GATT Service - Public API
 *
 * C header for integration with NimBLE C code
 */

#ifndef IMPROV_GATT_SERVICE_H
#define IMPROV_GATT_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Initialize the Improv WiFi GATT service
 * Registers the service and all characteristics with NimBLE
 */
void improv_gatt_service_init(void);

/**
 * Start the Improv WiFi GATT service
 * Called after BLE stack initialization
 */
void improv_gatt_service_start(void);

/**
 * Set the current BLE connection handle
 * Called when a client connects
 *
 * @param handle BLE connection handle
 */
void improv_set_connection_handle(uint16_t handle);

/**
 * Update WiFi provisioning status
 * Called by WiFi provisioning task to update Improv state
 *
 * @param status WiFi status code:
 *               0 = idle
 *               1 = connecting
 *               2 = connected (success)
 *               3 = failed
 */
void improv_update_wifi_status(uint8_t status);

/**
 * Check provisioning status early (before BLE init)
 * Returns 1 if device is fully provisioned, 0 otherwise
 */
int check_provisioning_status_early(void);

#ifdef __cplusplus
}
#endif

#endif /* IMPROV_GATT_SERVICE_H */
