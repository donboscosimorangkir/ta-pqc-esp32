# Compile HQC-1, HQC-3, dan HQC-5 sekaligus.
# Setiap level menggunakan namespace berbeda agar tidak terjadi
# bentrok nama fungsi.

set(HQC1_DIR
    src/liboqs/src/kem/hqc/pqc-hqc_hqc-1_ref
)

set(HQC3_DIR
    src/liboqs/src/kem/hqc/pqc-hqc_hqc-3_ref
)

set(HQC5_DIR
    src/liboqs/src/kem/hqc/pqc-hqc_hqc-5_ref
)

file(GLOB HQC1_SRCS
    "${CMAKE_CURRENT_LIST_DIR}/${HQC1_DIR}/*.c"
)

file(GLOB HQC3_SRCS
    "${CMAKE_CURRENT_LIST_DIR}/${HQC3_DIR}/*.c"
)

file(GLOB HQC5_SRCS
    "${CMAKE_CURRENT_LIST_DIR}/${HQC5_DIR}/*.c"
)

set(HQC1_WRAPPER
    src/liboqs/src/kem/hqc/kem_hqc_1.c
)

set(HQC3_WRAPPER
    src/liboqs/src/kem/hqc/kem_hqc_3.c
)

set(HQC5_WRAPPER
    src/liboqs/src/kem/hqc/kem_hqc_5.c
)

idf_component_register(
    SRCS
        ${HQC1_WRAPPER}
        ${HQC1_SRCS}

        ${HQC3_WRAPPER}
        ${HQC3_SRCS}

        ${HQC5_WRAPPER}
        ${HQC5_SRCS}

        hqc_component.c
        randombytes_oqs.c

    INCLUDE_DIRS
        "include"
        "${HQC1_DIR}"
        "${HQC3_DIR}"
        "${HQC5_DIR}"

    REQUIRES
        david-cermak__liboqs_mlkem
)

# ============================================================
# Namespace HQC-1
# ============================================================

set_source_files_properties(
    ${HQC1_WRAPPER}
    ${HQC1_SRCS}
    PROPERTIES
    COMPILE_DEFINITIONS
        "HQC_ARCH_REF=1;PQCHQC_NAMESPACE_PREFIX=PQCHQC_HQC1_C_;USE_OQS_RANDOMBYTES"
)

# ============================================================
# Namespace HQC-3
# ============================================================

set_source_files_properties(
    ${HQC3_WRAPPER}
    ${HQC3_SRCS}
    PROPERTIES
    COMPILE_DEFINITIONS
        "HQC_ARCH_REF=1;PQCHQC_NAMESPACE_PREFIX=PQCHQC_HQC3_C_;USE_OQS_RANDOMBYTES"
)

# ============================================================
# Namespace HQC-5
# ============================================================

set_source_files_properties(
    ${HQC5_WRAPPER}
    ${HQC5_SRCS}
    PROPERTIES
    COMPILE_DEFINITIONS
        "HQC_ARCH_REF=1;PQCHQC_NAMESPACE_PREFIX=PQCHQC_HQC5_C_;USE_OQS_RANDOMBYTES"
)

# DIAGNOSA: catat pemakaian stack per fungsi (file .su). Hapus setelah selesai.
target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
