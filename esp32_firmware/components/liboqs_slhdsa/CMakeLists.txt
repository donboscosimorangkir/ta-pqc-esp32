# liboqs_slhdsa - SLH-DSA-SHAKE-128s / 192s / 256s (FIPS 205)
# - slh_dsa_c dikompilasi SEKALI (runtime dispatch lewat slh_param_t)
# - Tanpa wrapper OQS_SIG_*, tanpa slh_sha2.c / sha2_*.c / slh_prehash.c
# - <oqs/oqs.h> dan fungsi OQS_* di-reuse dari component liboqs_mldsa

set(SLH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/slh_dsa_c")

idf_component_register(
    SRCS
        slhdsa_generic.c
        slh_dsa_c/slh_dsa.c
        slh_dsa_c/slh_shake.c
        slh_dsa_c/sha3_api.c
        slh_dsa_c/sha3_f1600.c
    INCLUDE_DIRS
        "."
    REQUIRES
        liboqs_mldsa
)

target_include_directories(${COMPONENT_LIB} PRIVATE
    ${SLH_DIR}
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-error
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-unused-function
    -Wno-maybe-uninitialized
)
