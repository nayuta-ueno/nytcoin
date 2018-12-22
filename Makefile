PROJECT_NAME := nytcoin
PRJ_PATH = .
OBJECT_DIRECTORY = _build
OUTPUT_BINARY_DIRECTORY = .
OUTPUT_FILENAME := $(PROJECT_NAME)

export OUTPUT_FILENAME
MAKEFILE_NAME := $(MAKEFILE_LIST)
MAKEFILE_DIR := $(dir $(MAKEFILE_NAME) )

#GNU_PREFIX := arm-none-eabi-

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
NO_ECHO :=
else
NO_ECHO := @
endif

# Toolchain commands
CC       		:= "$(GNU_PREFIX)gcc"
#CC       		:= "$(GNU_PREFIX)clang"
AS       		:= "$(GNU_PREFIX)as"
AR       		:= "$(GNU_PREFIX)ar" -r
LD       		:= "$(GNU_PREFIX)ld"
NM       		:= "$(GNU_PREFIX)nm"
OBJDUMP  		:= "$(GNU_PREFIX)objdump"
OBJCOPY  		:= "$(GNU_PREFIX)objcopy"
SIZE    		:= "$(GNU_PREFIX)size"

#function for removing duplicates in a list
remduplicates = $(strip $(if $1,$(firstword $1) $(call remduplicates,$(filter-out $(firstword $1),$1))))

#sources project
C_SOURCE_FILES += $(PRJ_PATH)/src/bc_proto.c
C_SOURCE_FILES += $(PRJ_PATH)/src/bc_flash.c
C_SOURCE_FILES += $(PRJ_PATH)/src/bc_network.c
C_SOURCE_FILES += $(PRJ_PATH)/src/main.c

#assembly files common to all targets
#ASM_SOURCE_FILES  = $(SDK_PATH)/some.s

#includes
INC_PATHS += -I$(PRJ_PATH)/include
INC_PATHS += -Ilibs
INC_PATHS += -Ilibs/ptarmbtc/include

LISTING_DIRECTORY = $(OBJECT_DIRECTORY)

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY) $(LISTING_DIRECTORY) )

######################################
#CFLAGS
######################################
# cpu
#CFLAGS += -mcpu=cortex-m0
#CFLAGS += -mthumb -mabi=aapcs
#CFLAGS += -mfloat-abi=soft

CFLAGS += --std=gnu99
CFLAGS += -Wall

# keep every function in separate section. This will allow linker to dump unused functions
#CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
#CFLAGS += -flto -fno-builtin

# others


######################################
#LDFLAGS
######################################
# cpu
#LDFLAGS += -mcpu=cortex-m0

# keep every function in separate section. This will allow linker to dump unused functions
#LDFLAGS += -Xlinker -Map=$(LISTING_DIRECTORY)/$(OUTPUT_FILENAME).map

# let linker to dump unused sections
#LDFLAGS += -Wl,--gc-sections

# use newlib in nano version
#LDFLAGS += --specs=nano.specs -lc -lnosys

#POSIX thread
LDFLAGS += -pthread

#Link Library
LIBSTT += \
	libs/libbloom/build/libbloom.a \
	libs/ptarmbtc/lib/libbtc.a \
	libs/ptarmbtc/lib/libutl.a \
	libs/ptarmbtc/lib/libmbedcrypto.a \
	libs/ptarmbtc/lib/libbase58.a
LIBDYN += -lm

#default target - first one defined
default: all

#building all targets
all: libbloom .Depend
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

vpath %.c $(C_PATHS)

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

debug: CFLAGS += -DDEBUG
debug: CFLAGS += -ggdb3 -O0
debug: ASMFLAGS += -DDEBUG -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBSTT) $(LIBDYN) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

release: CFLAGS += -DNDEBUG -O3
release: ASMFLAGS += -DNDEBUG -O3
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

## Create build directories
$(BUILD_DIRECTORIES):
	$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<): $(CFLAGS)
	$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -c -o $@ $<


# Assemble files
$(OBJECT_DIRECTORY)/%.o: %.s
	@echo Compiling ASM file: $(notdir $<)
	$(NO_ECHO)$(CC) $(ASMFLAGS) $(INC_PATHS) -c -o $@ $<

libbloom:
	git submodule update --init --recursive
	make -C libs/libbloom MURMURHASH_VERSION=3


# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME).exe $(OUTPUT_BINARY_DIRECTORY)/*.stackdump .Depend

distclean: clean
	@make -C libs/libbloom clean

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) $(CFLAGS_ONLY) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.c=%.o)) $(SRC) >> .Depend; )
endif

-include .Depend
