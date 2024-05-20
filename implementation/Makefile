RUNAS_VERSION = 0.1.2

CC = gcc
CFLAGS += -Wall -g
LIBS = -lcrypt
TARGET = runas
SRCS = runas.c read_passwd.c authenticate.c common.c

# Define build directory (modify if needed)
BUILD_DIR = build

# Define object files relative to build directory
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

# Define install directory
INSTALL_DIR = /usr/bin

# Check if -DRUNAS_AUTH_PAM is in CFLAGS
ifneq (,$(findstring -DRUNAS_AUTH_PAM,$(CFLAGS)))
    LIBS += -lpam
    RUNAS_VERSION := $(RUNAS_VERSION) PAM
endif

CFLAGS += -DRUNAS_VERSION=\""$(RUNAS_VERSION)"\"

# Define all rule (builds the program)
all: $(BUILD_DIR)/$(TARGET)

# Ensure build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Define rule to compile each object file
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Define rule to build the program
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Define install rule (requires root privileges)
install: $(BUILD_DIR)/$(TARGET)
	cp $(BUILD_DIR)/$(TARGET) $(INSTALL_DIR)/
	chown root:root $(INSTALL_DIR)/$(TARGET)
	chmod 4755 $(INSTALL_DIR)/$(TARGET)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

# Define clean rule (removes object files and binary from build folder)
clean:
	rm -f $(BUILD_DIR)/*.o
	
# Static build
CRYPT_LIB_PATH := $(shell find /usr/lib/ /lib/ -name libcrypt.a 2>/dev/null | head -n 1)

check-crypt-path:
	@if [ -z "$(CRYPT_LIB_PATH)" ]; then \
	    echo "Error: libcrypt.a not found. Please ensure that the static library is available."; \
	    exit 1; \
	fi

static: check-crypt-path $(BUILD_DIR)/$(TARGET)-static
$(BUILD_DIR)/$(TARGET)-static: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -Wl,-Bstatic $(CRYPT_LIB_PATH) -Wl,-Bdynamic $(filter-out -lcrypt, $(LIBS))

.PHONY: clean install uninstall static
