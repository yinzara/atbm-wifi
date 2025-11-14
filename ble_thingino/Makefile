#
# Thingino BLE GATT Server - Improv WiFi Provisioning
#
# This Makefile builds the ble-gatt-server executable for Thingino devices.
# It references the NimBLE stack from the ble_host directory.
#

# Toolchain commands
CROSS_COMPILE ?= /wifi_prj/staff/zhouzhanchao/android4_4_SIN/Source/lichee/brandy/gcc-linaro/bin/arm-linux-gnueabi-
CC      := $(CROSS_COMPILE)gcc
CXX     := $(CROSS_COMPILE)g++
LD      := $(CROSS_COMPILE)gcc
AR      := $(CROSS_COMPILE)ar
AS      := $(CROSS_COMPILE)as
NM      := $(CROSS_COMPILE)nm
OBJDUMP := $(CROSS_COMPILE)objdump
OBJCOPY := $(CROSS_COMPILE)objcopy
SIZE    := $(CROSS_COMPILE)size

# Configuration
CONFIG_LINUX_BLE_STACK_APP = y
CONFIG_LINUX_BLE_STACK_LIB = n

# Directory paths
BLE_HOST_ROOT := $(abspath ../ble_host)
NIMBLE_ROOT   := $(BLE_HOST_ROOT)/nimble_v42
SRC_DIR       := $(abspath src)

# Source files - Improv WiFi implementation only
SRC := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/ble.c \
	$(SRC_DIR)/cli_stubs.c \
	$(SRC_DIR)/improv/improv.c \
	$(SRC_DIR)/improv_gatt_service.c

# Include NimBLE host components (minimal set for Improv WiFi)
include $(NIMBLE_ROOT)/Makefile_host.include

# Skip files that don't build for this port
NIMBLE_IGNORE := \
	$(NIMBLE_ROOT)/porting/nimble/src/hal_timer.c \
	$(NIMBLE_ROOT)/porting/nimble/src/os_cputime.c \
	$(NIMBLE_ROOT)/porting/nimble/src/os_cputime_pwr2.c

# Add OS layer sources from ble_host
# Note: Transport layer is provided by Makefile_host.include (ioctl for CONFIG_LINUX_BLE_STACK_APP=y)
SRC += \
	$(wildcard $(BLE_HOST_ROOT)/os/linux_app/src/*.c) \
	$(wildcard $(BLE_HOST_ROOT)/os/linux_app/src/*.cc)

# Include paths
INC := \
	$(SRC_DIR) \
	$(BLE_HOST_ROOT)/include \
	$(BLE_HOST_ROOT)/os/linux_app/include \
	$(NIMBLE_ROOT)/apps \
	$(NIMBLE_ROOT)/cli \
	$(NIMBLE_ROOT)/nimble/transport/ioctl/include

INCLUDES := $(addprefix -I, $(INC))
INCLUDES += $(NIMBLE_INCLUDE_PATH)

# Object files
SRC_C  := $(filter %.c,  $(SRC))
SRC_CC := $(filter %.cc, $(SRC))

OBJ := $(SRC_C:.c=.o)
OBJ += $(SRC_CC:.cc=.o)

# Filter out conflicting files from LIB_NIMBLE_SRC that we've replaced
# We replace: main.o, ble.o, cli.o, ble_at_cmd.o, and btshell
NIMBLE_OBJ_FILTERED := $(filter-out \
	$(NIMBLE_ROOT)/apps/main.o \
	$(NIMBLE_ROOT)/apps/ble.o \
	$(NIMBLE_ROOT)/cli/cli.o \
	$(NIMBLE_ROOT)/cli/ble_at_cmd.o \
	$(NIMBLE_ROOT)/apps/btshell/% \
	,$(LIB_NIMBLE_SRC))

OBJ += $(NIMBLE_OBJ_FILTERED)

TINYCRYPT_OBJ := $(NIMBLE_EXT_SRC)

# Compiler flags
CFLAGS := \
	$(NIMBLE_CFLAGS) \
	$(INCLUDES) \
	-g \
	-D_GNU_SOURCE \
	-Os \
	-fPIC \
	-DCONFIG_LINUX_BLE_STACK_APP=1 \
	-DCONFIG_BLE_PTS_TEST_MOD=0

# Linker flags
LDFLAGS := -static
LIBS := $(NIMBLE_LDFLAGS) -lstdc++ -lrt -lpthread

# Targets
.PHONY: all clean install

all: ble-gatt-server

clean:
	rm -f $(OBJ)
	rm -f ble-gatt-server
	rm -f ble-gatt-server.S

install: ble-gatt-server
	cp -f ble-gatt-server $(BLE_HOST_ROOT)/../driver_install/

# Compilation rules
$(TINYCRYPT_OBJ): CFLAGS+=$(TINYCRYPT_CFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

%.o: %.cc
	$(CXX) -c $(CFLAGS) -o $@ $<

# Link executable
ble-gatt-server: $(OBJ) $(TINYCRYPT_OBJ)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(SIZE) $@
	$(OBJDUMP) -d -S $@ > ble-gatt-server.S
	$(CROSS_COMPILE)strip $@ --strip-unneeded
	@echo ""
	@echo "========================================="
	@echo "Build complete: ble-gatt-server"
	@echo "========================================="
	@echo ""
