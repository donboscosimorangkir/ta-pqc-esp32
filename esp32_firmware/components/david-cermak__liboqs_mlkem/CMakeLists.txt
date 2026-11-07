set(kem_common_SRCS
    src/liboqs/src/common/pqclean_shims/fips202.c
    src/liboqs/src/common/pqclean_shims/fips202x4.c
    src/liboqs/src/common/sha3/sha3.c
    src/liboqs/src/common/sha3/xkcp_sha3.c
    src/liboqs/src/common/sha3/sha3x4.c
    src/liboqs/src/common/sha3/xkcp_sha3x4.c
    src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
    src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c
    src/liboqs/src/kem/kem.c
    src/liboqs/src/common/common.c
    src/liboqs/src/kem/ml_kem/kem_ml_kem_512.c
    src/liboqs/src/kem/ml_kem/kem_ml_kem_768.c
    src/liboqs/src/kem/ml_kem/kem_ml_kem_1024.c
    randombytes.c
    mlkem_generic.c
    mlkem.c
    mlkem768.c
)

idf_component_register(
    SRCS ${kem_common_SRCS}
    INCLUDE_DIRS "." "include"
)

target_include_directories(${COMPONENT_LIB} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/sha3
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600times4/serial
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    OQS_ENABLE_KEM_ml_kem_512
    OQS_ENABLE_KEM_ml_kem_768
    OQS_ENABLE_KEM_ml_kem_1024
)

# ============================================================
# ML-KEM-512 native reference
# ============================================================

set(MLKEM_512_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-512_ref
)

add_library(ml_kem_512_ref OBJECT
    ${MLKEM_512_DIR}/mlkem/src/compress.c
    ${MLKEM_512_DIR}/mlkem/src/debug.c
    ${MLKEM_512_DIR}/mlkem/src/indcpa.c
    ${MLKEM_512_DIR}/mlkem/src/kem.c
    ${MLKEM_512_DIR}/mlkem/src/poly.c
    ${MLKEM_512_DIR}/mlkem/src/poly_k.c
    ${MLKEM_512_DIR}/mlkem/src/sampling.c
    ${MLKEM_512_DIR}/mlkem/src/verify.c
)

target_compile_options(ml_kem_512_ref PUBLIC
    -DMLK_CONFIG_PARAMETER_SET=512
    -DMLK_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_kem_512_ref PRIVATE
    ${MLKEM_512_DIR}
    ${MLKEM_512_DIR}/mlkem/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_kem_512_ref>
)

# ============================================================
# ML-KEM-768 native reference
# ============================================================

set(MLKEM_768_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-768_ref
)

add_library(ml_kem_768_ref OBJECT
    ${MLKEM_768_DIR}/mlkem/src/compress.c
    ${MLKEM_768_DIR}/mlkem/src/debug.c
    ${MLKEM_768_DIR}/mlkem/src/indcpa.c
    ${MLKEM_768_DIR}/mlkem/src/kem.c
    ${MLKEM_768_DIR}/mlkem/src/poly.c
    ${MLKEM_768_DIR}/mlkem/src/poly_k.c
    ${MLKEM_768_DIR}/mlkem/src/sampling.c
    ${MLKEM_768_DIR}/mlkem/src/verify.c
)

target_compile_options(ml_kem_768_ref PUBLIC
    -DMLK_CONFIG_PARAMETER_SET=768
    -DMLK_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_kem_768_ref PRIVATE
    ${MLKEM_768_DIR}
    ${MLKEM_768_DIR}/mlkem/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_kem_768_ref>
)

# ============================================================
# ML-KEM-1024 native reference
# ============================================================

set(MLKEM_1024_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-1024_ref
)

add_library(ml_kem_1024_ref OBJECT
    ${MLKEM_1024_DIR}/mlkem/src/compress.c
    ${MLKEM_1024_DIR}/mlkem/src/debug.c
    ${MLKEM_1024_DIR}/mlkem/src/indcpa.c
    ${MLKEM_1024_DIR}/mlkem/src/kem.c
    ${MLKEM_1024_DIR}/mlkem/src/poly.c
    ${MLKEM_1024_DIR}/mlkem/src/poly_k.c
    ${MLKEM_1024_DIR}/mlkem/src/sampling.c
    ${MLKEM_1024_DIR}/mlkem/src/verify.c
)

target_compile_options(ml_kem_1024_ref PUBLIC
    -DMLK_CONFIG_PARAMETER_SET=1024
    -DMLK_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_kem_1024_ref PRIVATE
    ${MLKEM_1024_DIR}
    ${MLKEM_1024_DIR}/mlkem/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_kem_1024_ref>
)
