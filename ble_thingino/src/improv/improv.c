#include "improv.h"
#include <string.h>
#include <stdlib.h>

improv_command_data_t improv_parse_data(const uint8_t *data, size_t length, bool check_checksum)
{
    improv_command_data_t result;
    result.command = IMPROV_COMMAND_UNKNOWN;
    result.ssid = NULL;
    result.password = NULL;
    result.data = NULL;

    if (length < 2) {
        return result;
    }

    improv_command_t command = (improv_command_t)data[0];
    uint8_t data_length = data[1];

    /* Verify data length matches */
    if (data_length != length - 2 - (check_checksum ? 1 : 0)) {
        return result;
    }

    /* Validate checksum if requested */
    if (check_checksum) {
        if (length < 3) {
            return result;
        }

        uint8_t checksum = data[length - 1];
        uint32_t calculated_checksum = 0;

        for (size_t i = 0; i < length - 1; i++) {
            calculated_checksum += data[i];
        }

        if ((uint8_t)calculated_checksum != checksum) {
            result.command = IMPROV_COMMAND_BAD_CHECKSUM;
            return result;
        }
    }

    /* Parse WIFI_SETTINGS command (two strings: SSID + password) */
    if (command == IMPROV_COMMAND_WIFI_SETTINGS) {
        if (length < 3) {
            return result;
        }

        uint8_t ssid_length = data[2];
        size_t ssid_start = 3;
        size_t ssid_end = ssid_start + ssid_length;

        if (ssid_end > length) {
            return result;
        }

        if (ssid_end >= length) {
            return result;
        }

        uint8_t pass_length = data[ssid_end];
        size_t pass_start = ssid_end + 1;
        size_t pass_end = pass_start + pass_length;

        if (pass_end > length) {
            return result;
        }

        /* Allocate and copy SSID */
        result.ssid = (char*)malloc(ssid_length + 1);
        if (result.ssid == NULL) {
            return result;
        }
        memcpy(result.ssid, data + ssid_start, ssid_length);
        result.ssid[ssid_length] = '\0';

        /* Allocate and copy password */
        result.password = (char*)malloc(pass_length + 1);
        if (result.password == NULL) {
            free(result.ssid);
            result.ssid = NULL;
            return result;
        }
        memcpy(result.password, data + pass_start, pass_length);
        result.password[pass_length] = '\0';

        result.command = command;
        return result;
    }

    /* Parse single-string commands (hostname, password, timezone, proxy host, proxy port) */
    if (command == IMPROV_COMMAND_SET_HOSTNAME ||
        command == IMPROV_COMMAND_SET_ROOT_PASSWORD ||
        command == IMPROV_COMMAND_SET_TIMEZONE ||
        command == IMPROV_COMMAND_SET_PROXY_HOST ||
        command == IMPROV_COMMAND_SET_PROXY_PORT) {

        if (length < 3) {
            return result;
        }

        uint8_t str_length = data[2];
        size_t str_start = 3;
        size_t str_end = str_start + str_length;

        if (str_end > length) {
            return result;
        }

        /* Allocate and copy string data */
        result.data = (char*)malloc(str_length + 1);
        if (result.data == NULL) {
            return result;
        }
        memcpy(result.data, data + str_start, str_length);
        result.data[str_length] = '\0';

        result.command = command;
        return result;
    }

    /* Parse PROXY_ENABLE command (single byte: 0x00/0x01) */
    if (command == IMPROV_COMMAND_SET_PROXY_ENABLE) {
        if (length < 3) {
            return result;
        }

        /* Data is just a single byte: enabled (1) or disabled (0) */
        result.data = (char*)malloc(2);
        if (result.data == NULL) {
            return result;
        }
        result.data[0] = data[2];
        result.data[1] = '\0';

        result.command = command;
        return result;
    }

    /* For other commands, just return the command type */
    result.command = command;
    return result;
}

improv_rpc_response_t improv_build_rpc_response(improv_command_t command,
                                                 const char **strings,
                                                 size_t string_count,
                                                 bool add_checksum)
{
    improv_rpc_response_t response;
    response.data = NULL;
    response.length = 0;

    /* Calculate frame length */
    /* Fixed: command (1) + data_length (1) + checksum (1 if add_checksum) */
    size_t frame_length = 2 + (add_checksum ? 1 : 0);

    /* Variable: string count + sum of all string lengths */
    frame_length += string_count;
    for (size_t i = 0; i < string_count; i++) {
        if (strings[i] != NULL) {
            frame_length += strlen(strings[i]);
        }
    }

    /* Allocate buffer */
    response.data = (uint8_t*)malloc(frame_length);
    if (response.data == NULL) {
        return response;
    }
    response.length = frame_length;

    /* Fill buffer */
    response.data[0] = (uint8_t)command;

    /* Copy strings with length prefixes */
    size_t pos = 2;  /* Start after command and data_length */
    for (size_t i = 0; i < string_count; i++) {
        size_t str_len = 0;
        if (strings[i] != NULL) {
            str_len = strlen(strings[i]);
        }

        response.data[pos] = (uint8_t)str_len;
        pos++;

        if (str_len > 0) {
            memcpy(response.data + pos, strings[i], str_len);
            pos += str_len;
        }
    }

    /* Set data length field */
    response.data[1] = (uint8_t)(pos - 2);

    /* Add checksum if requested */
    if (add_checksum) {
        uint32_t calculated_checksum = 0;
        for (size_t i = 0; i < frame_length - 1; i++) {
            calculated_checksum += response.data[i];
        }
        response.data[frame_length - 1] = (uint8_t)(calculated_checksum & 0xFF);
    }

    return response;
}

void improv_free_command_data(improv_command_data_t *cmd)
{
    if (cmd == NULL) {
        return;
    }

    if (cmd->ssid != NULL) {
        free(cmd->ssid);
        cmd->ssid = NULL;
    }

    if (cmd->password != NULL) {
        free(cmd->password);
        cmd->password = NULL;
    }

    if (cmd->data != NULL) {
        free(cmd->data);
        cmd->data = NULL;
    }

    cmd->command = IMPROV_COMMAND_UNKNOWN;
}

void improv_free_response(improv_rpc_response_t *response)
{
    if (response == NULL) {
        return;
    }

    if (response->data != NULL) {
        free(response->data);
        response->data = NULL;
    }

    response->length = 0;
}
