PROJECT := otp
SRC := src/$(PROJECT).c src/base32.c src/hex.c
TARGET := lib/$(PROJECT).so
CFLAGS := -fPIC -O2 -fomit-frame-pointer -Wall -Werror -pipe -D__STDC_FORMAT_MACROS
#CFLAGS += -g -DDEBUG -O0
LDFLAGS := -lcrypto
CC := gcc
PPP_VERSION := 2.4.5
PLUGIN_FILE := /usr/lib/pppd/$(PPP_VERSION)/$(PROJECT).so

BUILD := .build
OBJ := $(SRC:%.c=$(BUILD)/%.o)

all $(PROJECT): $(TARGET)

$(shell mkdir -p $(BUILD))
$(shell $(CC) $(CFLAGS) -MM $(SRC) > $(BUILD)/.depend)
include $(BUILD)/.depend

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(shell dirname $@)
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	@mkdir -p $(shell dirname $@)
	@echo LD $(shell basename $@)
	@$(CC) -shared -o $(TARGET) $(OBJ) $(LDFLAGS)

run: $(PLUGIN_FILE)
	@sudo strace /usr/sbin/pptpd -f

install: $(PLUGIN_FILE)

$(PLUGIN_FILE): $(TARGET)
	@echo CP $(shell basename $(TARGET))
	@sudo cp $(TARGET) $(PLUGIN_FILE)

clean:
	@echo RM $(shell basename $(TARGET)) $(BUILD)
	@rm -rf $(TARGET) $(BUILD)

