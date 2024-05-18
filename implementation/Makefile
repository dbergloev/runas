CC = gcc
CFLAGS = -Wall -g
LIBS = -lcrypt
TARGET = runas
SRCS = runas.c read_passwd.c authenticate.c

# Define object files (automatically generated)
OBJS = $(SRCS:.c=.o)

# Define install directory
INSTALL_DIR = /usr/bin

# Define all rule (builds the program)
all: $(TARGET)

# Define rule to compile each object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Define rule to build the program
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Define install rule (requires root privileges)
install: $(TARGET)
	cp $(TARGET) $(INSTALL_DIR)/
	chown root:root $(INSTALL_DIR)/$(TARGET)
	chmod 4755 $(INSTALL_DIR)/$(TARGET)
	
uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

# Define clean rule (removes object files)
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean install uninstall

