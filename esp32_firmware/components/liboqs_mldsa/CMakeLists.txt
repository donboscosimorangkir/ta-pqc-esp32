set(sig_common_SRCS
    src/liboqs/src/common/pqclean_shims/fips202.c
    src/liboqs/src/common/pqclean_shims/fips202x4.c
    src/liboqs/src/common/sha3/sha3.c
    src/liboqs/src/common/sha3/xkcp_sha3.c
    src/liboqs/src/common/sha3/sha3x4.c
    src/liboqs/src/common/sha3/xkcp_sha3x4.c
    src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
    src/liboqs/src/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c
    src/liboqs/src/common/common.c
    src/liboqs/src/sig/ml_dsa/sig_ml_dsa_44.c
    src/liboqs/src/sig/ml_dsa/sig_ml_dsa_65.c
    src/liboqs/src/sig/ml_dsa/sig_ml_dsa_87.c
    mldsa_generic.c
    randombytes.c
)

idf_component_register(
    SRCS ${sig_common_SRCS}
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
    OQS_ENABLE_SIG_ml_dsa_44
    OQS_ENABLE_SIG_ml_dsa_65
    OQS_ENABLE_SIG_ml_dsa_87
)

# ============================================================
# ML-DSA-44 native reference
# ============================================================

set(MLDSA_44_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref
)

add_library(ml_dsa_44_ref OBJECT
    ${MLDSA_44_DIR}/mldsa/src/ct.c
    ${MLDSA_44_DIR}/mldsa/src/debug.c
    ${MLDSA_44_DIR}/mldsa/src/packing.c
    ${MLDSA_44_DIR}/mldsa/src/poly.c
    ${MLDSA_44_DIR}/mldsa/src/poly_kl.c
    ${MLDSA_44_DIR}/mldsa/src/polyvec.c
    ${MLDSA_44_DIR}/mldsa/src/polyvec_lazy.c
    ${MLDSA_44_DIR}/mldsa/src/sign.c
)

target_compile_options(ml_dsa_44_ref PUBLIC
    -DMLD_CONFIG_PARAMETER_SET=44
    -DMLD_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_dsa_44_ref PRIVATE
    ${MLDSA_44_DIR}
    ${MLDSA_44_DIR}/mldsa/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_dsa_44_ref>
)

# ============================================================
# ML-DSA-65 native reference
# ============================================================

set(MLDSA_65_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref
)

add_library(ml_dsa_65_ref OBJECT
    ${MLDSA_65_DIR}/mldsa/src/ct.c
    ${MLDSA_65_DIR}/mldsa/src/debug.c
    ${MLDSA_65_DIR}/mldsa/src/packing.c
    ${MLDSA_65_DIR}/mldsa/src/poly.c
    ${MLDSA_65_DIR}/mldsa/src/poly_kl.c
    ${MLDSA_65_DIR}/mldsa/src/polyvec.c
    ${MLDSA_65_DIR}/mldsa/src/polyvec_lazy.c
    ${MLDSA_65_DIR}/mldsa/src/sign.c
)

target_compile_options(ml_dsa_65_ref PUBLIC
    -DMLD_CONFIG_PARAMETER_SET=65
    -DMLD_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_dsa_65_ref PRIVATE
    ${MLDSA_65_DIR}
    ${MLDSA_65_DIR}/mldsa/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_dsa_65_ref>
)

# ============================================================
# ML-DSA-87 native reference
# ============================================================

set(MLDSA_87_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref
)

add_library(ml_dsa_87_ref OBJECT
    ${MLDSA_87_DIR}/mldsa/src/ct.c
    ${MLDSA_87_DIR}/mldsa/src/debug.c
    ${MLDSA_87_DIR}/mldsa/src/packing.c
    ${MLDSA_87_DIR}/mldsa/src/poly.c
    ${MLDSA_87_DIR}/mldsa/src/poly_kl.c
    ${MLDSA_87_DIR}/mldsa/src/polyvec.c
    ${MLDSA_87_DIR}/mldsa/src/polyvec_lazy.c
    ${MLDSA_87_DIR}/mldsa/src/sign.c
)

target_compile_options(ml_dsa_87_ref PUBLIC
    -DMLD_CONFIG_PARAMETER_SET=87
    -DMLD_CONFIG_FILE="../../integration/liboqs/config_c.h"
)

target_include_directories(ml_dsa_87_ref PRIVATE
    ${MLDSA_87_DIR}
    ${MLDSA_87_DIR}/mldsa/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/liboqs/src/common/pqclean_shims
)

target_sources(${COMPONENT_LIB} PRIVATE
    $<TARGET_OBJECTS:ml_dsa_87_ref>
)

# DIAGNOSA: catat pemakaian stack per fungsi (file .su). Hapus setelah selesai.
target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)

# DIAGNOSA: ukur stack inti ML-DSA. Hapus setelah selesai.
target_compile_options(ml_dsa_87_ref PRIVATE -fstack-usage)
target_compile_options(ml_dsa_65_ref PRIVATE -fstack-usage)
