######## SGX SDK Settings ########
SGX_SDK	 ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
ENCLAVE_PPL_DIR=.
ENCLAVE_COMMONS_DIR=../EnclaveCommons
DRIVER_OPENSSL_DIR=../Openssl

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_ENCLAVE_SIGNER := $(BUILD_DIR)/sgx_sign
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		STL_PORT_INC := $(LINUX_SDK_DIR)/tlibstdcxx
		SGX_SDK ?= /opt/intel/sgxsdk
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		STL_PORT_INC := $(SGX_SDK_INC)
	endif

endif

ifdef DEBUG
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to build with SgxSSL libraries
#OPENSSL_PACKAGE := /home/gsd/Intel_SGX_SSL/intel-sgx-ssl/Linux/package
OPENSSL_PACKAGE := /opt/intel/sgxssl
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/
#TSETJMP_LIB := -lsgx_tsetjmp

ifdef DEBUG
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE	
endif
endif
endif

Aux_C_Files :=  $(wildcard $(DRIVER_OPENSSL_DIR)/*.c)
Enclave_commons_c_files := $(wildcard $(ENCLAVE_COMMONS_DIR)/*.c) 

EnclavePPL_C_Files :=  $(wildcard *.c) 
EnclavePPL_C_Objects :=  $(Enclave_commons_c_files:.c=.o) $(Aux_C_Files:.c=.o)  bin/$(EnclavePPL_C_Files:.c=.o)

Enclave_Include_Paths := -I$(ENCLAVE_COMMONS_DIR) -I$(ENCLAVE_PPL_DIR) -I$(DRIVER_OPENSSL_DIR) -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc -I$(STL_PORT_INC)/stlport -I$(OPENSSL_PACKAGE)/include -I$(OPENSSL_PACKAGE)/include/openssl

AR			  = ar
AR_FLAGS	  = rcs

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(Enclave_Include_Paths) -include "tsgxsslio.h"
EnclavePPL_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

PRIVATE_KEY       	 = $(ENCLAVE_COMMONS_DIR)/Enclave_private.pem
PUBLIC_KEY        	 = $(ENCLAVE_COMMONS_DIR)/Enclave_public_key.pem
KEY_SIZE          	 = 3072
LIB_DIRS         	 = -L$(SGX_LIBRARY_PATH)

ENCLAVEPPL			 = EnclavePPL
ENCLAVEPPL_EDL       = $(ENCLAVEPPL).edl
ENCLAVEPPL_CONFIG    = $(ENCLAVEPPL).config.xml
OUTPUTPPL_T          = $(ENCLAVEPPL).signed.so
OUTPUTPPL_T_UNSIG    = bin/$(ENCLAVEPPL).so
TRUSTEDPPL_CODE      = sgx_edger8r/$(ENCLAVEPPL)_t.c sgx_edger8r/$(ENCLAVEPPL)_t.h 
TRUSTEDPPL_OBJECTS   = bin/$(ENCLAVEPPL)_t.o
UNTRUSTEDPPL_OBJECTS = bin/$(ENCLAVEPPL)_u.o
UNTRUSTEDPPL_CODE    = sgx_edger8r/$(ENCLAVEPPL)_u.c sgx_edger8r/$(ENCLAVEPPL)_u.h 
OUTPUTPPL_U          = libenclave_ppl.a

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVEPPL).lds
	
.SILENT:
all: $(OUTPUTPPL_U) bin/$(OUTPUTPPL_T)
	
$(OUTPUTPPL_T_UNSIG): $(TRUSTEDPPL_OBJECTS) $(EnclavePPL_C_Objects)
	@mkdir -p bin
	@echo "COMMAND =>  $^"
	@$(CC) $^ -o $@ $(Enclave_Link_Flags) 
	@echo "LINK =>  $@"

bin/$(OUTPUTPPL_T): $(OUTPUTPPL_T_UNSIG)
	@mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(PRIVATE_KEY) -enclave $< -out $@ -config $(ENCLAVEPPL_CONFIG)
	@echo "SIGN =>  $@"

$(OUTPUTPPL_U): $(UNTRUSTEDPPL_OBJECTS)
	@mkdir -p bin
	$(AR) $(AR_FLAGS) $@ $<

$(UNTRUSTEDPPL_CODE): $(SGX_EDGER8R) $(ENCLAVEPPL_EDL)
	@mkdir -p sgx_edger8r
	$(SGX_EDGER8R) --untrusted $(ENCLAVEPPL_EDL) --search-path $(OPENSSL_PACKAGE)/include --search-path $(SGX_SDK_INC) --untrusted-dir sgx_edger8r
	@echo "GEN  =>  $@"

$(UNTRUSTEDPPL_OBJECTS): $(UNTRUSTEDPPL_CODE)
	@mkdir -p bin
	@$(CC) $(Common_C_Cpp_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(TRUSTEDPPL_CODE): $(SGX_EDGER8R) $(ENCLAVEPPL_EDL)
	@mkdir -p sgx_edger8r
	$(SGX_EDGER8R) --trusted $(ENCLAVEPPL_EDL)  --search-path $(ENCLAVE_PPL_DIR) --search-path $(OPENSSL_PACKAGE)/include --search-path $(SGX_SDK_INC) --trusted-dir sgx_edger8r
	@echo "GEN  =>  $@"


$(TRUSTEDPPL_OBJECTS): $(TRUSTEDPPL_CODE)
	@mkdir -p bin
	@$(CC) $(EnclavePPL_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

bin/%.o: %.c 
	@$(CC) $(EnclavePPL_C_Flags) -c $< -o $@
	@echo "CC   <=  $^"

%.o: %.c %.h 
	@$(CC) $(EnclavePPL_C_Flags) -c $< -o $@
	@echo "CC   <=  $^"

ifeq ($(PREFIX),)
    PREFIX := /opt/trustfs
endif

install: bin/$(OUTPUTPPL_T)
	@mkdir -p $(PREFIX)
	cp bin/$(OUTPUTPPL_T) $(PREFIX)/$(OUTPUTPPL_T)

uninstall:
	echo "$(INDENT)[RM]" $(PREFIX)/$(OUTPUTPPL_T)
	$(RM) $(PREFIX)/$(OUTPUTPPL_T)

.PHONY: force_check
force_check:
	true

.PHONY: scrub
scrub: 
	echo "$(INDENT)[RM]  " $(PRIVATE_KEY) $(PUBLIC_KEY)
	$(RM) $(PRIVATE_KEY) $(PUBLIC_KEY)

.PHONY: configure
configure: 
	echo "$(INDENT)[GEN] $(PRIVATE_KEY) ($(KEY_SIZE) bits)"

	# generate 3072 bit private RSA key
	openssl genrsa -out $(PRIVATE_KEY) -3 $(KEY_SIZE)
	
	echo "$(INDENT)[EXT] $(PUBLIC_KEY)"
	# extract public key
	openssl rsa -in $(PRIVATE_KEY) -pubout -out $(PUBLIC_KEY) 
	
	# sign enclave
	#sgx_sign sign -key private_key.pem -enclave Enclave/tresorencl.so -out tresorencl.signed.so
	
.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(Enclave_C_Objects) 
	$(RM) $(Enclave_C_Objects) 

	echo "$(INDENT)[RM]" $(ENCLAVE_COMMONS_DIR)/*.o
	$(RM) $(ENCLAVE_COMMONS_DIR)/*.o
	
	echo "$(INDENT)[RM]" $(OUTPUTPPL_T_UNSIG) $(OUTPUTPPL_T)
	$(RM) $(OUTPUTPPL_T_UNSIG) $(OUTPUTPPL_T)
	
	echo "$(INDENT)[RM]" $(TRUSTEDPPL_OBJECTS)
	$(RM) $(TRUSTEDPPL_OBJECTS)
	
	echo "$(INDENT)[RM]" $(TRUSTEDPPL_CODE)
	$(RM) $(TRUSTEDPPL_CODE)
	
	echo "$(INDENT)[RM]" $(UNTRUSTEDPPL_OBJECTS)
	$(RM) $(UNTRUSTEDPPL_OBJECTS)
	
	echo "$(INDENT)[RM]" $(UNTRUSTEDPPL_CODE)
	$(RM) $(UNTRUSTEDPPL_CODE)
	
	echo "$(INDENT)[RM]" $(OUTPUTPPL_U)
	$(RM) $(OUTPUTPPL_U)

	echo "$(INDENT)[RM]" $(DRIVER_OPENSSL_DIR)/*.o
	$(RM) $(DRIVER_OPENSSL_DIR)/*.o

	echo "$(INDENT)[RM]" bin/
	$(RM) -r bin/

	echo "$(INDENT)[RM]" sgx_edger8r/
	$(RM) -r sgx_edger8r/
	
