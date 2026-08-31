cmake_minimum_required(VERSION 3.22)

project(tfed448 VERSION 0.1.0 LANGUAGES C)

include(CTest)

option(TF_ED448_SANITIZE "Build host tests with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(TF_ED448_STACK_USAGE "Emit compiler .su stack-usage files" OFF)

set(TF_ED448_SOURCES
    src/tf_ed448.c
    src/libdecaf/utils.c
    src/libdecaf/shake.c
    src/libdecaf/p448/arch_32/f_impl.c
    src/libdecaf/p448/f_arithmetic.c
    src/libdecaf/ed448goldilocks/decaf_tables.c
    src/libdecaf/generated/p448/f_generic.c
    src/libdecaf/generated/ed448goldilocks/scalar.c
    src/libdecaf/generated/ed448goldilocks/decaf.c
    src/libdecaf/generated/ed448goldilocks/eddsa.c
)

add_library(tfed448 STATIC ${TF_ED448_SOURCES})
add_library(tfed448::tfed448 ALIAS tfed448)

target_include_directories(tfed448
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
        src/libdecaf/include
        src/libdecaf/include/arch_32
        src/libdecaf/p448
        src/libdecaf/p448/arch_32
        src/libdecaf/generated/p448
)
target_compile_definitions(tfed448 PRIVATE DECAF_WORD_BITS=32)
target_compile_features(tfed448 PRIVATE c_std_99)
target_compile_options(tfed448 PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wno-error=attributes
    -Wno-unused-parameter
    -fno-strict-aliasing
    -ffunction-sections
    -fdata-sections
)

if(CMAKE_CROSSCOMPILING)
    target_compile_options(tfed448 PRIVATE
        "-include${CMAKE_CURRENT_SOURCE_DIR}/src/tf_ed448_portable_endian.h"
    )
endif()

if(TF_ED448_STACK_USAGE)
    target_compile_options(tfed448 PRIVATE -fstack-usage)
endif()

if(TF_ED448_SANITIZE)
    target_compile_options(tfed448 PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-optimize-sibling-calls
    )
    target_link_options(tfed448 PRIVATE -fsanitize=address,undefined)
endif()

install(TARGETS tfed448 EXPORT tfed448-targets ARCHIVE DESTINATION lib)
install(FILES include/tf_ed448.h DESTINATION include)
install(EXPORT tfed448-targets NAMESPACE tfed448:: DESTINATION lib/cmake/tfed448)

if(BUILD_TESTING)
    find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)

    add_executable(tf_ed448_tests tests/test_tf_ed448.c)
    target_link_libraries(tf_ed448_tests PRIVATE tfed448)
    target_compile_options(tf_ed448_tests PRIVATE -Wall -Wextra -Werror)
    target_link_options(tf_ed448_tests PRIVATE -Wl,--gc-sections)

    add_executable(tf_ed448_openssl_tests tests/test_openssl_interop.c)
    target_link_libraries(tf_ed448_openssl_tests PRIVATE tfed448 OpenSSL::Crypto)
    target_compile_options(tf_ed448_openssl_tests PRIVATE -Wall -Wextra -Werror)
    target_link_options(tf_ed448_openssl_tests PRIVATE -Wl,--gc-sections)

    if(TF_ED448_SANITIZE)
        foreach(test_target tf_ed448_tests tf_ed448_openssl_tests)
            target_compile_options(${test_target} PRIVATE
                -fsanitize=address,undefined
                -fno-omit-frame-pointer
                -fno-optimize-sibling-calls
            )
            target_link_options(${test_target} PRIVATE -fsanitize=address,undefined)
        endforeach()
    endif()

    add_test(NAME tf_ed448_tests COMMAND tf_ed448_tests)
    add_test(NAME tf_ed448_openssl_tests COMMAND tf_ed448_openssl_tests)
endif()
