cmake_minimum_required(VERSION 3.13.0)
project(keymanager)
 
# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Locate SGX SDK
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_SDK_PATH}/include)

# Locate CURL
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

# SGX configuration
set(SGX_DEBUG_MODE 1)

set(ENCLAVE_SRC
		enclave/enclave.cpp
		enclave/enclave_t.c
	)

add_library(enclave SHARED ${ENCLAVE_SRC})
set_target_properties(enclave PROPERTIES PREFIX "")
target_include_directories(enclave PRIVATE
							${SGX_INCLUDE_DIR}
							${SGX_TLIBC_INCLUDE_DIR}
							${SGX_TLIBCXX_INCLUDE_DIR}
							)
target_link_directories(enclave PRIVATE ${SGX_SDK_PATH}/lib64)
target_compile_options(enclave PRIVATE
        -nostdinc
        -fvisibility=hidden
        -fpie
        -ffunction-sections
        -fdata-sections
        -fstack-protector-strong
        -std=c++11
        -nostdinc++
        )
target_link_options(enclave PRIVATE
		-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles
		-Bstatic -Bsymbolic
		-Wl,-pie,-eenclave_entry
		-Wl,--export-dynamic
		-Wl,--defsym,__ImageBase=0
		-Wl,--gc-sections
		-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.lds
		)

target_link_libraries(enclave
		-Wl,--whole-archive sgx_trts_sim
		-Wl,--no-whole-archive
		-Wl,--start-group
		sgx_tservice_sim
		sgx_tkey_exchange
		sgx_pthread
		sgx_tstdc
		sgx_tcxx
		sgx_tcrypto
		-Wl,--end-group
		)

add_custom_command(
	DEPENDS enclave/enclave.edl
	PRE_BUILD COMMAND ${SGX_EDGER8R}
	--trusted --untrusted enclave/enclave.edl
	--search-path ${SGX_INCLUDE_DIR}
	--trusted-dir enclave --untrusted-dir enclave
	OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_t.h
		   ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_t.c
		   ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_u.h
		   ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave_u.c
	)

add_custom_command(TARGET enclave POST_BUILD 
        COMMAND openssl genrsa -out enclave/enclave.pem -3 3072
		COMMAND ${SGX_ENCLAVE_SIGNER} sign
        -key ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.pem
		-enclave ./enclave.so
		-out ${CMAKE_BINARY_DIR}/enclave.sign.so
        -config ${CMAKE_CURRENT_SOURCE_DIR}/enclave/enclave.config.xml
        )


# Test executable
add_executable(run test.cpp enclave/enclave_u.c)
add_dependencies(run enclave)
target_include_directories(run PUBLIC enclave/)
target_link_directories(run PRIVATE ${SGX_LIBRARY_PATH})
target_link_libraries(run ${GTEST_LIBRARIES} ${CURL_LIBRARIES} sgx_urts_sim sgx_uae_service_sim sgx_ukey_exchange)
