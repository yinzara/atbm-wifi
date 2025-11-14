#ifndef IMPROV_H
#define IMPROV_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Improv WiFi Service UUIDs */
#define IMPROV_SERVICE_UUID         "00467768-6228-2272-4663-277478268000"
#define IMPROV_STATUS_UUID          "00467768-6228-2272-4663-277478268001"
#define IMPROV_ERROR_UUID           "00467768-6228-2272-4663-277478268002"
#define IMPROV_RPC_COMMAND_UUID     "00467768-6228-2272-4663-277478268003"
#define IMPROV_RPC_RESULT_UUID      "00467768-6228-2272-4663-277478268004"
#define IMPROV_CAPABILITIES_UUID    "00467768-6228-2272-4663-277478268005"

/* Error codes */
typedef enum {
    IMPROV_ERROR_NONE = 0x00,
    IMPROV_ERROR_INVALID_RPC = 0x01,
    IMPROV_ERROR_UNKNOWN_RPC = 0x02,
    IMPROV_ERROR_UNABLE_TO_CONNECT = 0x03,
    IMPROV_ERROR_NOT_AUTHORIZED = 0x04,
    IMPROV_ERROR_UNKNOWN = 0xFF,
} improv_error_t;

/* Provisioning states */
typedef enum {
    IMPROV_STATE_STOPPED = 0x00,
    IMPROV_STATE_AWAITING_AUTHORIZATION = 0x01,
    IMPROV_STATE_AUTHORIZED = 0x02,
    IMPROV_STATE_PROVISIONING = 0x03,
    IMPROV_STATE_PROVISIONED = 0x04,
} improv_state_t;

/* RPC Commands */
typedef enum {
    IMPROV_COMMAND_UNKNOWN = 0x00,
    IMPROV_COMMAND_WIFI_SETTINGS = 0x01,
    IMPROV_COMMAND_IDENTIFY = 0x02,
    IMPROV_COMMAND_SCAN_WIFI = 0x03,        /* CUSTOM: Thingino WiFi scan extension */
    IMPROV_COMMAND_GET_DEVICE_INFO = 0x04,
    /* Thingino configuration extensions */
    IMPROV_COMMAND_SET_HOSTNAME = 0x10,     /* Set device hostname */
    IMPROV_COMMAND_SET_ROOT_PASSWORD = 0x11,/* Set root password (SHA-512) */
    IMPROV_COMMAND_SET_TIMEZONE = 0x12,     /* Set timezone (e.g., America/Los_Angeles) */
    IMPROV_COMMAND_SET_PROXY_ENABLE = 0x13, /* Enable/disable ESP32 proxy (0x00/0x01) */
    IMPROV_COMMAND_SET_PROXY_HOST = 0x14,   /* Set proxy host address */
    IMPROV_COMMAND_SET_PROXY_PORT = 0x15,   /* Set proxy port number */
    IMPROV_COMMAND_BAD_CHECKSUM = 0xFF,
} improv_command_t;

/* Capabilities */
#define IMPROV_CAPABILITY_IDENTIFY 0x01

/* Serial protocol types */
typedef enum {
    IMPROV_TYPE_CURRENT_STATE = 0x01,
    IMPROV_TYPE_ERROR_STATE = 0x02,
    IMPROV_TYPE_RPC = 0x03,
    IMPROV_TYPE_RPC_RESPONSE = 0x04
} improv_serial_type_t;

#define IMPROV_SERIAL_VERSION 1

/* Parsed command structure */
typedef struct {
    improv_command_t command;
    char *ssid;      /* Caller must free - for WIFI_SETTINGS */
    char *password;  /* Caller must free - for WIFI_SETTINGS */
    char *data;      /* Caller must free - for single-string commands */
} improv_command_data_t;

/* RPC response structure */
typedef struct {
    uint8_t *data;   /* Caller must free */
    size_t length;
} improv_rpc_response_t;

/*
 * Parse Improv data from buffer
 * Returns parsed command. Caller must free ssid and password if not NULL.
 * check_checksum: If true, validates checksum and returns BAD_CHECKSUM on failure
 */
improv_command_data_t improv_parse_data(const uint8_t *data, size_t length, bool check_checksum);

/*
 * Build RPC response with string array
 * strings: Array of null-terminated strings
 * string_count: Number of strings in array
 * add_checksum: If true, appends checksum byte
 * Returns response structure. Caller must free response.data
 */
improv_rpc_response_t improv_build_rpc_response(improv_command_t command,
                                                 const char **strings,
                                                 size_t string_count,
                                                 bool add_checksum);

/*
 * Free command data allocated by improv_parse_data
 */
void improv_free_command_data(improv_command_data_t *cmd);

/*
 * Free response data allocated by improv_build_rpc_response
 */
void improv_free_response(improv_rpc_response_t *response);

#ifdef __cplusplus
}
#endif

#endif /* IMPROV_H */
