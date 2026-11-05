# C-only ordinary SaBRe adapter. The core producer supplies the exact engine
# DSO and both headers; this file does not compile Detcore or another Rust runtime.
CC ?= cc
ENGINE_DIR ?=
ENGINE_INCLUDE_DIR ?=
OUT ?= ../../target/native
SABRE = ../../experimental/reverie-sabre
CFLAGS = -std=c11 -O2 -fPIC -fno-builtin -mgeneral-regs-only -Wall -Wextra -Werror
LDFLAGS = -shared -Wl,-z,now,-z,defs
# The pinned Nix compiler wrapper must not add its build-root search paths.
export NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu := 1

ifeq ($(strip $(ENGINE_DIR)),)
$(error ENGINE_DIR must name the bound core engine artifact directory)
endif
ifeq ($(strip $(ENGINE_INCLUDE_DIR)),)
$(error ENGINE_INCLUDE_DIR must name the matching core ABI header directory)
endif

.PHONY: all
all: $(OUT)/libhermit_engine_sabre.so

$(OUT):
	mkdir -m 700 -p $@

$(OUT)/libhermit_engine_sabre.so: sabre-shim.c $(ENGINE_INCLUDE_DIR)/hermit-engine-v1.h $(SABRE)/src/ffi/recursion_protector.c $(SABRE)/vendor/sabre/includes/plugins/sbr_api_defs.h $(SABRE)/vendor/sabre/includes/loader/backend_stats.h $(ENGINE_DIR)/libhermit_inguest_engine.so | $(OUT)
	$(CC) $(CFLAGS) -D__NX_INTERCEPT_RDTSC -I$(ENGINE_INCLUDE_DIR) -I$(SABRE)/vendor/sabre/includes -I$(SABRE)/vendor/sabre/includes/plugins $(LDFLAGS) -Wl,-Bsymbolic-functions -o $@ sabre-shim.c $(SABRE)/src/ffi/recursion_protector.c $(abspath $(ENGINE_DIR)/libhermit_inguest_engine.so)

# The absolute engine DT_NEEDED path binds the installed cohort. No library
# search path is needed. An ABI version alone does not establish compatibility.
