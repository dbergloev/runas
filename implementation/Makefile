CC = gcc
CFLAGS = -Wall -g
LIBS = -lcrypt
TARGET = runas
SRCS = runas.c read_passwd.c authenticate.c

# Define build directory (modify if needed)
BUILD_DIR = build

# Define object files relative to build directory
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

# Define install directory
INSTALL_DIR = /usr/bin

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

.PHONY: clean install uninstall
