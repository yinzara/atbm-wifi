# Thingino BLE GATT Server - Improv WiFi Provisioning

This directory contains a standalone BLE GATT server implementation for Thingino devices that provides WiFi provisioning using the [Improv WiFi](https://www.improv-wifi.com/) BLE standard.

## Overview

The `ble-gatt-server` executable provides a simple, standardized way to provision WiFi credentials on Thingino IP cameras via Bluetooth Low Energy.

### Features

- **Standard Improv WiFi Protocol** - Compatible with any Improv WiFi client app
- **WiFi Network Scanning** - Scan and list available WiFi networks
- **Thingino Configuration** - Extended RPC commands for device setup:
  - Set hostname
  - Set root password
  - Set timezone
  - Configure ESP32 proxy settings
- **Auto-Provisioning Detection** - Automatically exits if device is already provisioned
- **Force Mode** - `-f` flag to start even when provisioned

## Directory Structure

```
ble_thingino/
├── Makefile               # Build configuration
├── README.md              # This file
└── src/
    ├── main.c             # Entry point and BLE stack initialization
    ├── ble.c              # BLE sync callback and advertising
    ├── improv_gatt_service.c  # Improv WiFi GATT service
    ├── improv_gatt_service.h  # Service API
    └── improv/
        ├── improv.c       # Improv protocol parser
        └── improv.h       # Improv protocol definitions
```

## Building

The Makefile references the NimBLE stack from the `../ble_host` directory. No modifications to `ble_host` are required.

```bash
cd ble_thingino
make
```

The output executable is `ble-gatt-server`.

## Usage

### Basic Usage

```bash
./ble-gatt-server
```

### Force Mode (Ignore Provisioning Status)

```bash
./ble-gatt-server -f
```

### Command Line Options

- `-f` - Force mode: Start BLE service even if device is already provisioned

## How It Works

1. **Provisioning Check**: On startup, checks if device is provisioned by looking for:
   - WiFi SSID (`fw_printenv wlan_ssid`)
   - Custom hostname (`fw_printenv hostname`)

2. **Graceful Exit**: If both are set and `-f` is not provided, exits cleanly

3. **BLE Advertising**: If not provisioned, starts advertising as `{hostname}-setup`

4. **Service Registration**: Registers Improv WiFi GATT service with 5 characteristics:
   - Current State (Read/Notify)
   - Error State (Read/Notify)
   - RPC Command (Write)
   - RPC Result (Read/Notify)
   - Capabilities (Read)

5. **WiFi Provisioning**: Accepts WiFi credentials and writes them to U-Boot environment

## Improv WiFi Protocol

### Commands

- `0x01` - **WiFi Settings**: Provision WiFi credentials (SSID + password)
- `0x02` - **Identify**: Play identification tone
- `0x03` - **Scan WiFi**: Scan and return list of available networks as a list of strings delimited as {ssid}|{security:WPA,WPA2,WEP,OPEN}|{strength}" like "MyNetwork|WPA|-43"
- `0x04` - **Get Device Info**: Return firmware version, hardware version, device name 
- `0x10` - **Set Hostname**: Configure device hostname
- `0x11` - **Set Root Password**: Set root user password (SHA-512)
- `0x12` - **Set Timezone**: Set timezone (e.g., `America/Los_Angeles`)
- `0x13` - **Set Proxy Enable**: Enable/disable ESP32 proxy (`0x00`/`0x01`)
- `0x14` - **Set Proxy Host**: Set proxy host address
- `0x15` - **Set Proxy Port**: Set proxy port number

## Dependencies

### From ble_host

The build system automatically includes these components from `../ble_host`:

- **NimBLE Host Stack**: BLE protocol implementation
- **NimBLE Services**: GAP and GATT services
- **Tinycrypt**: Cryptographic primitives
- **OS Abstraction Layer**: Linux adaptation layer
- **Transport Layer**: Socket-based HCI transport

### Runtime Dependencies

- `fw_printenv` / `fw_setenv` - U-Boot environment tools
- `iw` - WiFi scanning
- `/sbin/wifi` - WiFi service control
- `iac` - Audio playback for identify tone (optional)

## Configuration Persistence

All configuration is stored in U-Boot environment variables:

- `wlan_ssid` - WiFi SSID
- `wlan_pass` - WiFi password
- `hostname` - Device hostname

These persist across reboots and are read by Thingino init scripts.

## BLE Advertising

The device advertises with:
- **Service UUID**: `00467768-6228-2272-4663-277478268000` (Improv WiFi)
- **Device Name**: `{hostname}-setup` (e.g., `geniesmartcam-setup`)
- **Advertising Interval**: 100ms

## Development

### Adding New RPC Commands

1. Add command enum to `src/improv/improv.h`
2. Update parser in `src/improv/improv.c`
3. Add handler in `src/improv_gatt_service.c`

### Modifying Build Configuration

Edit `Makefile` to change:
- Compiler flags (`CFLAGS`)
- Source files (`SRC`)
- Include paths (`INC`)
- Cross-compilation toolchain (`CROSS_COMPILE`)

## Troubleshooting

### Device Not Visible in BLE Scanner

- Check that BLE stack initialized: Look for `*** ADVERTISING STARTED ***` in log
- Verify WiFi driver coexistence mode is enabled
- Ensure device is not already provisioned (use `-f` to override)

### Provisioning Not Working

- Check U-Boot environment tools: `which fw_printenv fw_setenv`
- Verify WiFi service: `ls -l /sbin/wifi`
- Check log output for error messages

### Build Errors

- Ensure `ble_host` directory is at `../ble_host` relative to `ble_thingino`
- Verify NimBLE sources are intact in `ble_host/nimble_v42`
- Check cross-compilation toolchain path in `Makefile`

## License

Licensed under the Apache License, Version 2.0. See the NimBLE LICENSE file in `../ble_host/nimble_v42` for details.

## References

- [Improv WiFi Specification](https://www.improv-wifi.com/ble/)
- [Apache NimBLE](https://github.com/apache/mynewt-nimble)
- [Thingino Firmware](https://github.com/themactep/thingino-firmware)
