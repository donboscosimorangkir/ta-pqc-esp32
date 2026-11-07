# Get the path to ml-kem library
get_filename_component(ML_KEM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../impl/ml-kem" ABSOLUTE)

idf_component_register(SRCS "simple.cpp"
                    INCLUDE_DIRS "."
                    PRIV_INCLUDE_DIRS "${ML_KEM_ROOT}/include"
                                    "${ML_KEM_ROOT}/sha3/include"
                                    "${ML_KEM_ROOT}/subtle/include"
                                    "${ML_KEM_ROOT}/RandomShake/include")

# Set C++ standard to C++20 and increase constexpr evaluation limits
# This is needed for ml-kem's compile-time constant computations
# Note: ESP-IDF defaults to C++26, so we need to override it explicitly
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_20)

# Override ESP-IDF's default C++26 standard and set C++20
# Also add flags to handle ml-kem's constexpr computations and shift operations
# Note: ml-kem assumes 64-bit size_t but ESP32 uses 32-bit, causing shift warnings
target_compile_options(${COMPONENT_LIB} PRIVATE 
    $<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20>
    -fconstexpr-depth=1000
    -fconstexpr-ops-limit=10000000
    # Allow shift operations that may exceed bit width (ml-kem's operator^ assumes 64-bit)
    -fpermissive
    -Wno-error=shift-count-overflow
)
