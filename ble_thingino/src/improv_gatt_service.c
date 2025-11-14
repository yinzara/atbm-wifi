/*
 * Improv WiFi GATT Service Implementation
 *
 * Implements the Improv WiFi BLE standard for WiFi provisioning
 * Specification: https://www.improv-wifi.com/ble/
 *
 * Service UUID: 00467768-6228-2272-4663-277478268000
 *
 * Characteristics:
 * - Current State (0x8001) - Read/Notify - Provisioning state
 * - Error State (0x8002) - Read/Notify - Error codes
 * - RPC Command (0x8003) - Write - Commands from client
 * - RPC Result (0x8004) - Read/Notify - Command responses
 * - Capabilities (0x8005) - Read - Feature flags
 */

#include "improv/improv.h"
#include "improv_gatt_service.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/ble_gatt.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "atbm_debug.h"
#include "atbm_hal.h"
#include "atbm_os_api.h"

/*******************************************************************************
 * WiFi Provisioning Definitions
 ******************************************************************************/

#define MAX_SSID_LEN                    32
#define MAX_PASSWORD_LEN                64

/* WiFi network entry for temporary storage during scanning */
struct wifi_network {
    char ssid[MAX_SSID_LEN + 1];
    int signal;
    char security[16];
};

/**
 * Find existing network by SSID in the networks array
 * Returns index if found, -1 if not found
 */
static int find_network_by_ssid(struct wifi_network *networks, int count, const char *ssid)
{
    int i;
    for (i = 0; i < count; i++) {
        if (strcmp(networks[i].ssid, ssid) == 0) {
            return i;
        }
    }
    return -1;
}

/*******************************************************************************
 * Forward Declarations
 ******************************************************************************/

static int write_file_string(const char *filename, const char *value);

/*******************************************************************************
 * WiFi Provisioning Functions
 ******************************************************************************/

/* WiFi provisioning status */
static uint8_t wifi_status = 0;  /* 0=idle, 1=connecting, 2=connected, 3=failed */

/* Scan WiFi networks and return Improv-formatted results */
char* scan_wifi_networks_improv(void)
{
    FILE *fp;
    char line[512];
    char *result = NULL;
    size_t result_size = 4096;
    size_t result_len = 0;

    /* Temporary storage for parsing */
    char current_ssid[MAX_SSID_LEN + 1] = "";
    int current_signal = -100;
    char current_security[16] = "OPEN";
    int has_rsn = 0, has_wpa = 0, has_wpa3 = 0, has_privacy = 0;

    /* Storage for unique networks */
    struct wifi_network networks[50];
    int network_count = 0;
    int i, existing_idx;

    /* Allocate buffer for result */
    result = (char*)atbm_kmalloc(result_size, 0);
    if (!result) {
        iot_printf("[IMPROV-SCAN] Failed to allocate buffer\n");
        return NULL;
    }
    result[0] = '\0';

    /* Execute WiFi scan command */
    fp = popen("iw dev wlan0 scan 2>/dev/null", "r");
    if (!fp) {
        iot_printf("[IMPROV-SCAN] Failed to execute iw scan command\n");
        atbm_kfree(result);
        return NULL;
    }

    iot_printf("[IMPROV-SCAN] Scanning WiFi networks...\n");

    /* Parse scan output (same logic as scan_wifi_networks) */
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "BSS ") == line) {
            /* Process previous BSS if it has a valid SSID */
            if (current_ssid[0] != '\0') {
                /* Determine security type */
                if (has_wpa3) {
                    strcpy(current_security, "WPA3");
                } else if (has_rsn) {
                    strcpy(current_security, "WPA2");
                } else if (has_wpa) {
                    strcpy(current_security, "WPA");
                } else if (has_privacy) {
                    strcpy(current_security, "WEP");
                } else {
                    strcpy(current_security, "OPEN");
                }

                /* Check if we already have this SSID */
                existing_idx = find_network_by_ssid(networks, network_count, current_ssid);

                if (existing_idx >= 0) {
                    /* Keep stronger signal */
                    if (current_signal > networks[existing_idx].signal) {
                        networks[existing_idx].signal = current_signal;
                        strcpy(networks[existing_idx].security, current_security);
                    }
                } else if (network_count < 50) {
                    /* New SSID - add it */
                    strcpy(networks[network_count].ssid, current_ssid);
                    networks[network_count].signal = current_signal;
                    strcpy(networks[network_count].security, current_security);
                    network_count++;
                }
            }

            /* Reset for next BSS */
            current_ssid[0] = '\0';
            current_signal = -100;
            has_rsn = 0;
            has_wpa = 0;
            has_wpa3 = 0;
            has_privacy = 0;
        }
        else if (strstr(line, "SSID: ")) {
            char *ssid_start = strstr(line, "SSID: ") + 6;
            char *ssid_end = strchr(ssid_start, '\n');
            if (ssid_end) *ssid_end = '\0';

            while (*ssid_start == ' ' || *ssid_start == '\t') ssid_start++;

            if (*ssid_start != '\0') {
                strncpy(current_ssid, ssid_start, MAX_SSID_LEN);
                current_ssid[MAX_SSID_LEN] = '\0';
            }
        }
        else if (strstr(line, "signal:")) {
            char *sig_start = strstr(line, "signal:") + 7;
            current_signal = atoi(sig_start);
        }
        else if (strstr(line, "RSN:") || strstr(line, "WPA2")) {
            has_rsn = 1;
        }
        else if (strstr(line, "WPA:")) {
            has_wpa = 1;
        }
        else if (strstr(line, "WPA3")) {
            has_wpa3 = 1;
        }
        else if (strstr(line, "Privacy:")) {
            has_privacy = 1;
        }
    }

    /* Process last BSS */
    if (current_ssid[0] != '\0') {
        if (has_wpa3) {
            strcpy(current_security, "WPA3");
        } else if (has_rsn) {
            strcpy(current_security, "WPA2");
        } else if (has_wpa) {
            strcpy(current_security, "WPA");
        } else if (has_privacy) {
            strcpy(current_security, "WEP");
        } else {
            strcpy(current_security, "OPEN");
        }

        existing_idx = find_network_by_ssid(networks, network_count, current_ssid);
        if (existing_idx >= 0) {
            if (current_signal > networks[existing_idx].signal) {
                networks[existing_idx].signal = current_signal;
                strcpy(networks[existing_idx].security, current_security);
            }
        } else if (network_count < 50) {
            strcpy(networks[network_count].ssid, current_ssid);
            networks[network_count].signal = current_signal;
            strcpy(networks[network_count].security, current_security);
            network_count++;
        }
    }

    pclose(fp);

    /* Format results as Improv format: "SSID|security|strength\n" */
    for (i = 0; i < network_count; i++) {
        char entry[256];
        int len = snprintf(entry, sizeof(entry), "%s|%s|%d\n",
                          networks[i].ssid,
                          networks[i].security,
                          networks[i].signal);

        if (result_len + len < result_size - 1) {
            strcpy(result + result_len, entry);
            result_len += len;
        }
    }

    iot_printf("[IMPROV-SCAN] Found %d unique networks\n", network_count);
    return result;
}

/* Provision WiFi credentials */
void provision_wifi_from_improv(const char* ssid, const char* password)
{
    char cmd[512];
    int rc;

    if (!ssid) {
        iot_printf("[WIFI] NULL SSID\n");
        wifi_status = 3;  /* Failed */
        return;
    }

    iot_printf("[WIFI] Provisioning: %s\n", ssid);
    wifi_status = 1;  /* Connecting */

    /* Write WiFi SSID to U-Boot environment */
    snprintf(cmd, sizeof(cmd), "fw_setenv wlan_ssid \"%s\" 2>/dev/null", ssid);
    rc = system(cmd);
    if (rc != 0) {
        iot_printf("[WIFI] Warning: fw_setenv wlan_ssid failed: %d\n", rc);
    }

    /* Write WiFi password to U-Boot environment */
    if (password && strlen(password) > 0) {
        snprintf(cmd, sizeof(cmd), "fw_setenv wlan_pass \"%s\" 2>/dev/null", password);
    } else {
        snprintf(cmd, sizeof(cmd), "fw_setenv wlan_pass \"\" 2>/dev/null");
    }
    rc = system(cmd);
    if (rc != 0) {
        iot_printf("[WIFI] Warning: fw_setenv wlan_pass failed: %d\n", rc);
    }

    /* Trigger WiFi connection */
    iot_printf("[WIFI] Triggering WiFi restart...\n");
    rc = system("/sbin/wifi restart 2>/dev/null &");
    if (rc == 0) {
        wifi_status = 2;  /* Connected - assume success for now */
        iot_printf("[WIFI] WiFi restart triggered\n");
    } else {
        wifi_status = 3;  /* Failed */
        iot_printf("[WIFI] WiFi restart failed\n");
    }
}

/* Get WiFi provisioning status */
uint8_t get_wifi_provision_status(void)
{
    return wifi_status;
}

/*******************************************************************************
 * Provisioning Check
 ******************************************************************************/

/* Check if device is fully provisioned (WiFi + hostname configured) */
int check_provisioning_status_early(void)
{
    FILE *fp;
    char line[256];
    char value[128];
    int has_ssid = 0;
    int has_hostname = 0;

    iot_printf("[PROVISION-CHECK] Checking provisioning status...\n");

    /* Check WiFi SSID using fw_printenv */
    fp = popen("fw_printenv wlan_ssid 2>/dev/null", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp) != NULL && line[0] != '\0') {
            line[strcspn(line, "\n")] = '\0';
            /* Parse "wlan_ssid=VALUE" format */
            char *equals = strchr(line, '=');
            if (equals && strlen(equals + 1) > 0) {
                strncpy(value, equals + 1, sizeof(value) - 1);
                value[sizeof(value) - 1] = '\0';
                has_ssid = 1;
                iot_printf("[PROVISION-CHECK] Found WiFi SSID: '%s'\n", value);
            }
        }
        pclose(fp);
    }

    if (!has_ssid) {
        iot_printf("[PROVISION-CHECK] No wlan_ssid in U-Boot environment\n");
    }

    /* Check hostname using fw_printenv */
    fp = popen("fw_printenv hostname 2>/dev/null", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp) != NULL && line[0] != '\0') {
            line[strcspn(line, "\n")] = '\0';
            /* Parse "hostname=VALUE" format */
            char *equals = strchr(line, '=');
            if (equals && strlen(equals + 1) > 0) {
                strncpy(value, equals + 1, sizeof(value) - 1);
                value[sizeof(value) - 1] = '\0';
                if (strcmp(value, "thingino") != 0) {
                    has_hostname = 1;
                    iot_printf("[PROVISION-CHECK] Found custom hostname: '%s'\n", value);
                } else {
                    iot_printf("[PROVISION-CHECK] Hostname is default: '%s'\n", value);
                }
            }
        }
        pclose(fp);
    }

    if (!has_hostname) {
        iot_printf("[PROVISION-CHECK] No custom hostname in U-Boot environment\n");
    }

    /* Device is considered provisioned if both WiFi SSID and hostname are configured */
    int is_provisioned = (has_ssid && has_hostname);
    iot_printf("[PROVISION-CHECK] Result: %s (SSID=%d, Hostname=%d)\n",
               is_provisioned ? "PROVISIONED" : "NOT PROVISIONED",
               has_ssid, has_hostname);
    return is_provisioned;
}

/*******************************************************************************
 * Improv Service UUIDs
 ******************************************************************************/

/* Service UUID: 00467768-6228-2272-4663-277478268000 */
/* Non-static so it can be used for advertising */
const ble_uuid128_t improv_service_uuid =
    BLE_UUID128_INIT(0x00, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/* Current State: 00467768-6228-2272-4663-277478268001 */
static const ble_uuid128_t chr_current_state_uuid =
    BLE_UUID128_INIT(0x01, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/* Error State: 00467768-6228-2272-4663-277478268002 */
static const ble_uuid128_t chr_error_state_uuid =
    BLE_UUID128_INIT(0x02, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/* RPC Command: 00467768-6228-2272-4663-277478268003 */
static const ble_uuid128_t chr_rpc_command_uuid =
    BLE_UUID128_INIT(0x03, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/* RPC Result: 00467768-6228-2272-4663-277478268004 */
static const ble_uuid128_t chr_rpc_result_uuid =
    BLE_UUID128_INIT(0x04, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/* Capabilities: 00467768-6228-2272-4663-277478268005 */
static const ble_uuid128_t chr_capabilities_uuid =
    BLE_UUID128_INIT(0x05, 0x80, 0x26, 0x78, 0x74, 0x27, 0x63, 0x46,
                     0x72, 0x22, 0x28, 0x62, 0x68, 0x77, 0x46, 0x00);

/*******************************************************************************
 * State Variables
 ******************************************************************************/

static improv_state_t current_state = IMPROV_STATE_AUTHORIZED;  /* Auto-authorize on start */
static improv_error_t current_error = IMPROV_ERROR_NONE;
static uint8_t *rpc_result_data = NULL;
static size_t rpc_result_data_len = 0;
static uint16_t conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint8_t own_addr_type = BLE_OWN_ADDR_PUBLIC;

/* Notification handles */
static uint16_t current_state_notify_handle = 0;
static uint16_t error_state_notify_handle = 0;
static uint16_t rpc_result_notify_handle = 0;

/* Device info */
static const char* device_name = "Thingino";
static const char* firmware_version = "1.0.0";
static const char* hardware_version = "T31";

/* BLE advertising name (hostname + "-setup") */
static char ble_device_name[64] = "Improv-Setup";  /* Default fallback */
static char device_hostname[64] = "thingino";      /* Hostname for redirect URL */

/*******************************************************************************
 * Helper Functions
 ******************************************************************************/

static void get_ble_device_name(void)
{
    FILE *fp;
    char line[256];
    char hostname[64] = "thingino";  /* Default */

    /* Read hostname from U-Boot environment */
    fp = popen("fw_printenv hostname 2>/dev/null", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp) != NULL) {
            char *equals = strchr(line, '=');
            if (equals && strlen(equals + 1) > 0) {
                /* Remove trailing newline */
                char *newline = strchr(equals + 1, '\n');
                if (newline) *newline = '\0';
                strncpy(hostname, equals + 1, sizeof(hostname) - 1);
                hostname[sizeof(hostname) - 1] = '\0';
            }
        }
        pclose(fp);
    }

    /* Store hostname for redirect URL */
    strncpy(device_hostname, hostname, sizeof(device_hostname) - 1);
    device_hostname[sizeof(device_hostname) - 1] = '\0';

    /* Format BLE name as "{hostname}-setup" */
    snprintf(ble_device_name, sizeof(ble_device_name), "%s-setup", hostname);
    iot_printf("[IMPROV] BLE device name: %s\n", ble_device_name);
    iot_printf("[IMPROV] Redirect URL: http://%s.local\n", device_hostname);
}

static void send_notification(uint16_t handle, const void *data, size_t len)
{
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE || handle == 0) {
        return;
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (om == NULL) {
        iot_printf("[IMPROV] Failed to allocate mbuf for notification\n");
        return;
    }

    int rc = ble_gattc_notify_custom(conn_handle, handle, om);
    if (rc != 0) {
        iot_printf("[IMPROV] Notification failed: %d\n", rc);
    }
}

static void set_state(improv_state_t new_state)
{
    if (current_state != new_state) {
        current_state = new_state;
        iot_printf("[IMPROV] State changed to: 0x%02x\n", current_state);

        uint8_t state_byte = (uint8_t)current_state;
        send_notification(current_state_notify_handle, &state_byte, 1);
    }
}

static void set_error(improv_error_t new_error)
{
    if (current_error != new_error) {
        current_error = new_error;
        iot_printf("[IMPROV] Error set to: 0x%02x\n", current_error);

        uint8_t error_byte = (uint8_t)current_error;
        send_notification(error_state_notify_handle, &error_byte, 1);
    }
}

static void send_rpc_result(improv_command_t command, const char **strings, size_t string_count)
{
    /* Free previous result data */
    if (rpc_result_data != NULL) {
        free(rpc_result_data);
        rpc_result_data = NULL;
        rpc_result_data_len = 0;
    }

    /* Build RPC response */
    improv_rpc_response_t response = improv_build_rpc_response(command, strings, string_count, true);
    if (response.data == NULL) {
        return;
    }

    /* Store for read characteristic */
    rpc_result_data = response.data;
    rpc_result_data_len = response.length;

    iot_printf("[IMPROV] Sending RPC result for command 0x%02x, size: %zu\n",
               command, rpc_result_data_len);

    send_notification(rpc_result_notify_handle, rpc_result_data, rpc_result_data_len);
}

/*******************************************************************************
 * Configuration Utility Functions
 ******************************************************************************/

/* Write a string to a file */
static int write_file_string(const char *filename, const char *value)
{
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        iot_printf("[IMPROV] ERROR: Failed to open %s for writing\n", filename);
        return -1;
    }

    fprintf(fp, "%s\n", value);
    fclose(fp);

    iot_printf("[IMPROV] Wrote to %s: %s\n", filename, value);
    return 0;
}

/* Set root password using chpasswd with SHA-512 */
static int set_root_password(const char *password)
{
    FILE *passwd_fp = popen("chpasswd -c sha512", "w");
    if (!passwd_fp) {
        iot_printf("[IMPROV] ERROR: Failed to open chpasswd\n");
        return -1;
    }

    fprintf(passwd_fp, "root:%s\n", password);
    int rc = pclose(passwd_fp);

    if (rc == 0) {
        iot_printf("[IMPROV] Root password set successfully\n");
    } else {
        iot_printf("[IMPROV] ERROR: Failed to set root password (rc=%d)\n", rc);
    }

    return rc;
}

/*******************************************************************************
 * RPC Command Handlers
 ******************************************************************************/

static void handle_wifi_settings(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] WiFi Settings received\n");
    iot_printf("[IMPROV]   SSID: %s\n", cmd->ssid ? cmd->ssid : "(null)");
    iot_printf("[IMPROV]   Password length: %zu\n", cmd->password ? strlen(cmd->password) : 0);

    /* Check authorization */
    if (current_state != IMPROV_STATE_AUTHORIZED) {
        iot_printf("[IMPROV] ERROR: Not authorized\n");
        set_error(IMPROV_ERROR_NOT_AUTHORIZED);
        return;
    }

    /* Set state to provisioning */
    set_state(IMPROV_STATE_PROVISIONING);
    set_error(IMPROV_ERROR_NONE);

    /* Call WiFi provisioning function from thingino_gatt_server */
    provision_wifi_from_improv(cmd->ssid, cmd->password);
}

static void handle_identify(void)
{
    iot_printf("[IMPROV] Identify command received\n");

    /* Play identification tone */
    int rc = system("iac -f /usr/share/sounds/th-chime_1.pcm 2>/dev/null &");
    if (rc != 0) {
        iot_printf("[IMPROV] Warning: Failed to play identification tone\n");
    }

    /* Send empty RPC result to acknowledge */
    send_rpc_result(IMPROV_COMMAND_IDENTIFY, NULL, 0);
}

static void handle_scan_wifi(void)
{
    iot_printf("[IMPROV] Scan WiFi command received\n");

    /* Call WiFi scan function from thingino_gatt_server */
    /* This should return Improv-formatted scan results */
    char* scan_results = scan_wifi_networks_improv();

    if (scan_results == NULL) {
        iot_printf("[IMPROV] WiFi scan failed\n");
        set_error(IMPROV_ERROR_UNKNOWN);
        send_rpc_result(IMPROV_COMMAND_SCAN_WIFI, NULL, 0);
        return;
    }

    /* Parse scan results into array of strings */
    /* Format: "SSID1|WPA2|-45\nSSID2|OPEN|-67\n..." */

    /* First, count lines */
    size_t line_count = 0;
    char *scan_copy = strdup(scan_results);
    if (scan_copy == NULL) {
        free(scan_results);
        return;
    }

    char *line = strtok(scan_copy, "\n");
    while (line != NULL) {
        if (strlen(line) > 0) {
            line_count++;
        }
        line = strtok(NULL, "\n");
    }
    free(scan_copy);

    /* Allocate string array */
    const char **networks = (const char **)malloc(line_count * sizeof(char*));
    if (networks == NULL) {
        free(scan_results);
        return;
    }

    /* Parse again and store pointers */
    size_t idx = 0;
    line = strtok(scan_results, "\n");
    while (line != NULL && idx < line_count) {
        if (strlen(line) > 0) {
            networks[idx++] = line;
        }
        line = strtok(NULL, "\n");
    }

    iot_printf("[IMPROV] Found %zu networks\n", line_count);
    send_rpc_result(IMPROV_COMMAND_SCAN_WIFI, networks, line_count);

    free(networks);
    free(scan_results);
}

static void handle_get_device_info(void)
{
    iot_printf("[IMPROV] Get Device Info command received\n");

    const char *info[3];
    info[0] = firmware_version;
    info[1] = hardware_version;
    info[2] = device_name;

    send_rpc_result(IMPROV_COMMAND_GET_DEVICE_INFO, info, 3);
}

static void handle_set_hostname(const improv_command_data_t *cmd)
{
    char cmd_buf[256];
    int rc;

    iot_printf("[IMPROV] Set Hostname command received: %s\n", cmd->data ? cmd->data : "(null)");

    if (!cmd->data || strlen(cmd->data) == 0) {
        iot_printf("[IMPROV] ERROR: Empty hostname\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_HOSTNAME, (const char*[]){"ERROR"}, 1);
        return;
    }

    /* Write to /etc/hostname for system use */
    rc = write_file_string("/etc/hostname", cmd->data);
    if (rc != 0) {
        iot_printf("[IMPROV] ERROR: Failed to write /etc/hostname\n");
        send_rpc_result(IMPROV_COMMAND_SET_HOSTNAME, (const char*[]){"ERROR"}, 1);
        return;
    }

    /* Also write to U-Boot environment for persistence */
    snprintf(cmd_buf, sizeof(cmd_buf), "fw_setenv hostname \"%s\" 2>/dev/null", cmd->data);
    system(cmd_buf);

    /* Update the system hostname immediately */
    snprintf(cmd_buf, sizeof(cmd_buf), "hostname %s", cmd->data);
    system(cmd_buf);

    iot_printf("[IMPROV] Hostname set to: %s\n", cmd->data);
    send_rpc_result(IMPROV_COMMAND_SET_HOSTNAME, (const char*[]){"OK"}, 1);
}

static void handle_set_root_password(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] Set Root Password command received\n");

    if (!cmd->data || strlen(cmd->data) == 0) {
        iot_printf("[IMPROV] ERROR: Empty password\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_ROOT_PASSWORD, (const char*[]){"ERROR"}, 1);
        return;
    }

    int rc = set_root_password(cmd->data);
    if (rc == 0) {
        send_rpc_result(IMPROV_COMMAND_SET_ROOT_PASSWORD, (const char*[]){"OK"}, 1);
    } else {
        send_rpc_result(IMPROV_COMMAND_SET_ROOT_PASSWORD, (const char*[]){"ERROR"}, 1);
    }
}

static void handle_set_timezone(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] Set Timezone command received: %s\n", cmd->data ? cmd->data : "(null)");

    if (!cmd->data || strlen(cmd->data) == 0) {
        iot_printf("[IMPROV] ERROR: Empty timezone\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_TIMEZONE, (const char*[]){"ERROR"}, 1);
        return;
    }

    int rc = write_file_string("/etc/timezone", cmd->data);
    if (rc == 0) {
        send_rpc_result(IMPROV_COMMAND_SET_TIMEZONE, (const char*[]){"OK"}, 1);
    } else {
        send_rpc_result(IMPROV_COMMAND_SET_TIMEZONE, (const char*[]){"ERROR"}, 1);
    }
}

static void handle_set_proxy_enable(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] Set Proxy Enable command received\n");

    if (!cmd->data) {
        iot_printf("[IMPROV] ERROR: Missing enable/disable value\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_ENABLE, (const char*[]){"ERROR"}, 1);
        return;
    }

    uint8_t enabled = cmd->data[0];
    iot_printf("[IMPROV] Proxy enabled: %s\n", enabled ? "YES" : "NO");

    /* Write to config file */
    int rc = write_file_string("/etc/ble_proxy_enabled", enabled ? "1" : "0");
    if (rc == 0) {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_ENABLE, (const char*[]){"OK"}, 1);
    } else {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_ENABLE, (const char*[]){"ERROR"}, 1);
    }
}

static void handle_set_proxy_host(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] Set Proxy Host command received: %s\n", cmd->data ? cmd->data : "(null)");

    if (!cmd->data || strlen(cmd->data) == 0) {
        iot_printf("[IMPROV] ERROR: Empty proxy host\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_HOST, (const char*[]){"ERROR"}, 1);
        return;
    }

    int rc = write_file_string("/etc/ble_proxy_host", cmd->data);
    if (rc == 0) {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_HOST, (const char*[]){"OK"}, 1);
    } else {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_HOST, (const char*[]){"ERROR"}, 1);
    }
}

static void handle_set_proxy_port(const improv_command_data_t *cmd)
{
    iot_printf("[IMPROV] Set Proxy Port command received: %s\n", cmd->data ? cmd->data : "(null)");

    if (!cmd->data || strlen(cmd->data) == 0) {
        iot_printf("[IMPROV] ERROR: Empty proxy port\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_PORT, (const char*[]){"ERROR"}, 1);
        return;
    }

    int rc = write_file_string("/etc/ble_proxy_port", cmd->data);
    if (rc == 0) {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_PORT, (const char*[]){"OK"}, 1);
    } else {
        send_rpc_result(IMPROV_COMMAND_SET_PROXY_PORT, (const char*[]){"ERROR"}, 1);
    }
}

static void handle_rpc_command(const uint8_t *data, size_t len)
{
    iot_printf("[IMPROV] RPC Command received, length: %zu\n", len);

    /* Parse command using Improv SDK */
    improv_command_data_t cmd = improv_parse_data(data, len, true);

    if (cmd.command == IMPROV_COMMAND_BAD_CHECKSUM) {
        iot_printf("[IMPROV] ERROR: Bad checksum\n");
        set_error(IMPROV_ERROR_INVALID_RPC);
        improv_free_command_data(&cmd);
        return;
    }

    if (cmd.command == IMPROV_COMMAND_UNKNOWN) {
        iot_printf("[IMPROV] ERROR: Unknown command\n");
        set_error(IMPROV_ERROR_UNKNOWN_RPC);
        improv_free_command_data(&cmd);
        return;
    }

    iot_printf("[IMPROV] Command: 0x%02x\n", cmd.command);

    /* Handle specific commands */
    switch (cmd.command) {
        case IMPROV_COMMAND_WIFI_SETTINGS:
            handle_wifi_settings(&cmd);
            break;

        case IMPROV_COMMAND_IDENTIFY:
            handle_identify();
            break;

        case IMPROV_COMMAND_SCAN_WIFI:
            handle_scan_wifi();
            break;

        case IMPROV_COMMAND_GET_DEVICE_INFO:
            handle_get_device_info();
            break;

        case IMPROV_COMMAND_SET_HOSTNAME:
            handle_set_hostname(&cmd);
            break;

        case IMPROV_COMMAND_SET_ROOT_PASSWORD:
            handle_set_root_password(&cmd);
            break;

        case IMPROV_COMMAND_SET_TIMEZONE:
            handle_set_timezone(&cmd);
            break;

        case IMPROV_COMMAND_SET_PROXY_ENABLE:
            handle_set_proxy_enable(&cmd);
            break;

        case IMPROV_COMMAND_SET_PROXY_HOST:
            handle_set_proxy_host(&cmd);
            break;

        case IMPROV_COMMAND_SET_PROXY_PORT:
            handle_set_proxy_port(&cmd);
            break;

        default:
            iot_printf("[IMPROV] ERROR: Unsupported command: 0x%02x\n", cmd.command);
            set_error(IMPROV_ERROR_UNKNOWN_RPC);
            break;
    }

    improv_free_command_data(&cmd);
}

/*******************************************************************************
 * GATT Characteristic Access Callback
 ******************************************************************************/

static int improv_chr_access(uint16_t conn_handle_arg, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    const ble_uuid_t *uuid = ctxt->chr->uuid;
    int rc;

    /* Current State */
    if (ble_uuid_cmp(uuid, &chr_current_state_uuid.u) == 0) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            uint8_t state_byte = (uint8_t)current_state;
            rc = os_mbuf_append(ctxt->om, &state_byte, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }

    /* Error State */
    if (ble_uuid_cmp(uuid, &chr_error_state_uuid.u) == 0) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            uint8_t error_byte = (uint8_t)current_error;
            rc = os_mbuf_append(ctxt->om, &error_byte, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }

    /* RPC Command */
    if (ble_uuid_cmp(uuid, &chr_rpc_command_uuid.u) == 0) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            /* Get write data */
            uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
            uint8_t *write_data = (uint8_t*)malloc(om_len);
            if (write_data == NULL) {
                return BLE_ATT_ERR_INSUFFICIENT_RES;
            }

            rc = ble_hs_mbuf_to_flat(ctxt->om, write_data, om_len, NULL);
            if (rc != 0) {
                free(write_data);
                return BLE_ATT_ERR_INSUFFICIENT_RES;
            }

            /* Handle command */
            handle_rpc_command(write_data, om_len);
            free(write_data);

            return 0;
        }
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    /* RPC Result */
    if (ble_uuid_cmp(uuid, &chr_rpc_result_uuid.u) == 0) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            if (rpc_result_data == NULL || rpc_result_data_len == 0) {
                return 0;  /* No data */
            }
            rc = os_mbuf_append(ctxt->om, rpc_result_data, rpc_result_data_len);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }

    /* Capabilities */
    if (ble_uuid_cmp(uuid, &chr_capabilities_uuid.u) == 0) {
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            uint8_t capabilities = IMPROV_CAPABILITY_IDENTIFY;
            rc = os_mbuf_append(ctxt->om, &capabilities, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }

    return BLE_ATT_ERR_UNLIKELY;
}

/*******************************************************************************
 * GATT Service Definition
 ******************************************************************************/

static struct ble_gatt_chr_def improv_characteristics[] = {
    {
        /* Current State */
        .uuid = &chr_current_state_uuid.u,
        .access_cb = improv_chr_access,
        .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &current_state_notify_handle,
    },
    {
        /* Error State */
        .uuid = &chr_error_state_uuid.u,
        .access_cb = improv_chr_access,
        .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &error_state_notify_handle,
    },
    {
        /* RPC Command */
        .uuid = &chr_rpc_command_uuid.u,
        .access_cb = improv_chr_access,
        .flags = BLE_GATT_CHR_F_WRITE,
    },
    {
        /* RPC Result */
        .uuid = &chr_rpc_result_uuid.u,
        .access_cb = improv_chr_access,
        .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &rpc_result_notify_handle,
    },
    {
        /* Capabilities */
        .uuid = &chr_capabilities_uuid.u,
        .access_cb = improv_chr_access,
        .flags = BLE_GATT_CHR_F_READ,
    },
    {
        0, /* No more characteristics in this service */
    }
};

static const struct ble_gatt_svc_def improv_gatt_services[] = {
    {
        /* Improv WiFi Service */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &improv_service_uuid.u,
        .characteristics = improv_characteristics,
    },
    {
        0, /* No more services */
    },
};

/*******************************************************************************
 * Public API
 ******************************************************************************/

void improv_gatt_service_init(void)
{
    int rc;

    iot_printf("========================================\n");
    iot_printf("===  IMPROV WIFI SERVICE v1.0       ===\n");
    iot_printf("===  Standard BLE Provisioning      ===\n");
    iot_printf("========================================\n");
    iot_printf("[IMPROV] Initializing Improv WiFi GATT Service\n");

    /* Get BLE device name from hostname */
    get_ble_device_name();

    /* Note: Early provisioning check already happened in main.c
     * If we get here, we should register the service */

    /* Set initial state */
    current_state = IMPROV_STATE_AUTHORIZED;  /* Auto-authorize */
    current_error = IMPROV_ERROR_NONE;

    /* Register GATT service */
    rc = ble_gatts_count_cfg(improv_gatt_services);
    if (rc != 0) {
        iot_printf("[IMPROV] Error counting GATT services: %d\n", rc);
        return;
    }

    rc = ble_gatts_add_svcs(improv_gatt_services);
    if (rc != 0) {
        iot_printf("[IMPROV] Error adding GATT services: %d\n", rc);
        return;
    }

    iot_printf("[IMPROV] Improv WiFi GATT service registered\n");
    iot_printf("[IMPROV] - Service UUID: %s\n", IMPROV_SERVICE_UUID);
    iot_printf("[IMPROV] - 5 characteristics registered\n");
    iot_printf("[IMPROV] - Current State Handle: %d\n", current_state_notify_handle);
    iot_printf("[IMPROV] - Error State Handle: %d\n", error_state_notify_handle);
    iot_printf("[IMPROV] - RPC Result Handle: %d\n", rpc_result_notify_handle);
    iot_printf("[IMPROV] - Initial State: AUTHORIZED (0x02)\n");
}

/*******************************************************************************
 * GAP Event Handler
 ******************************************************************************/

static int improv_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        iot_printf("[IMPROV] GAP Connect event: status=%d\n", event->connect.status);
        if (event->connect.status == 0) {
            conn_handle = event->connect.conn_handle;
            iot_printf("[IMPROV] Connected: handle=%d\n", conn_handle);
        } else {
            /* Connection failed, resume advertising */
            iot_printf("[IMPROV] Connection failed, restarting advertising\n");
            improv_gatt_service_start();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        iot_printf("[IMPROV] GAP Disconnect event: reason=%d\n", event->disconnect.reason);
        conn_handle = BLE_HS_CONN_HANDLE_NONE;
        /* Resume advertising */
        improv_gatt_service_start();
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        iot_printf("[IMPROV] GAP Advertising complete\n");
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        iot_printf("[IMPROV] GAP Subscribe event: handle=%d\n", event->subscribe.attr_handle);
        break;

    default:
        break;
    }

    return 0;
}

/*******************************************************************************
 * Advertising Functions
 ******************************************************************************/

static void start_advertising(void)
{
    struct ble_gap_adv_params advp;
    int rc;

    /* Set advertising data - advertise the Improv WiFi service UUID only */
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));

    /* Advertise Improv WiFi service UUID */
    fields.uuids128 = (ble_uuid128_t[]){ improv_service_uuid };
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        iot_printf("[IMPROV] ERROR: Failed to set advertising data: %d\n", rc);
        return;
    }

    /* Set scan response data - device name (hostname + "-setup") */
    struct ble_hs_adv_fields rsp_fields;
    memset(&rsp_fields, 0, sizeof(rsp_fields));

    rsp_fields.name = (uint8_t *)ble_device_name;
    rsp_fields.name_len = strlen(ble_device_name);
    rsp_fields.name_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        iot_printf("[IMPROV] ERROR: Failed to set scan response data: %d\n", rc);
        return;
    }

    /* Set advertising parameters */
    memset(&advp, 0, sizeof(advp));
    advp.conn_mode = BLE_GAP_CONN_MODE_UND;  /* Undirected connectable */
    advp.disc_mode = BLE_GAP_DISC_MODE_GEN;  /* General discoverable */
    advp.itvl_min = 160;  /* 100ms (units of 0.625ms) */
    advp.itvl_max = 160;  /* 100ms */

    /* Start advertising */
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                           &advp, improv_gap_event_cb, NULL);
    if (rc != 0) {
        iot_printf("[IMPROV] ERROR: Failed to start advertising: %d\n", rc);
        return;
    }

    iot_printf("[IMPROV] *** ADVERTISING STARTED ***\n");
    iot_printf("[IMPROV] - Service UUID: 00467768-6228-2272-4663-277478268000\n");
    iot_printf("[IMPROV] - Device visible as '%s' in BLE scanners\n", ble_device_name);
}

/*******************************************************************************
 * Service Start
 ******************************************************************************/

void improv_gatt_service_start(void)
{
    int rc;

    /* Infer address type (BLE stack is already synced when this is called) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        iot_printf("[IMPROV] ERROR: Failed to infer address type: %d\n", rc);
        return;
    }

    iot_printf("[IMPROV] Starting Improv WiFi service...\n");

    /* Start advertising */
    start_advertising();
}

void improv_set_connection_handle(uint16_t handle)
{
    conn_handle = handle;
    iot_printf("[IMPROV] Connection handle set: %d\n", conn_handle);
}

void improv_update_wifi_status(uint8_t status)
{
    /*
     * Called from thingino_gatt_server during WiFi provisioning
     * status: 0=idle, 1=connecting, 2=connected, 3=failed
     */
    switch (status) {
        case 0:  /* Idle */
            set_state(IMPROV_STATE_AUTHORIZED);
            break;

        case 1:  /* Connecting */
            set_state(IMPROV_STATE_PROVISIONING);
            break;

        case 2: {  /* Connected */
            set_state(IMPROV_STATE_PROVISIONED);
            set_error(IMPROV_ERROR_NONE);

            /* Send URL in RPC result (optional redirect URL) */
            static char result_url[128];
            snprintf(result_url, sizeof(result_url), "http://%s.local", device_hostname);
            const char *url_ptr = result_url;
            send_rpc_result(IMPROV_COMMAND_WIFI_SETTINGS, &url_ptr, 1);
            break;
        }

        case 3:  /* Failed */
            set_state(IMPROV_STATE_AUTHORIZED);  /* Back to authorized */
            set_error(IMPROV_ERROR_UNABLE_TO_CONNECT);
            break;
    }
}
