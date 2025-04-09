cmake_minimum_required(VERSION 3.12)

project(qdrvm-crates C CXX)

include(cmake/add_rust_library.cmake)

list(APPEND QDRVM_ALL_CRATES schnorrkel arkworks bandersnatch_vrfs ark_ev_vrfs)
set(QDRVM_BIND_CRATES "" CACHE STRING "The list of crates to build.")
set_property(CACHE QDRVM_BIND_CRATES PROPERTY STRINGS ${QDRVM_ALL_CRATES})

foreach (CRATE ${QDRVM_BIND_CRATES})
    list(FIND QDRVM_ALL_CRATES ${CRATE} CRATE_IDX)
    if (CRATE_IDX EQUAL -1)
        message(FATAL_ERROR "Unknown crate '${CRATE}'. Available crates: ${QDRVM_ALL_CRATES}")
    endif()
    list(APPEND SELECTED_CRATES ${CRATE})
    set(${CRATE}_SELECTED TRUE)
endforeach()

list(LENGTH SELECTED_CRATES SELECTED_CRATE_NUM)
if (SELECTED_CRATE_NUM EQUAL 0)
    message(FATAL_ERROR "No crates selected using QDRVM_BIND_CRATES, at least one must be selected. Available crates: ${QDRVM_ALL_CRATES}")
endif()

foreach (CRATE ${SELECTED_CRATES})
    add_rust_library(${CRATE} HEADER_FILE ${PROJECT_SOURCE_DIR}/generated/include/${CRATE}/${CRATE}.h LIB_NAME ${CRATE}_crust)
endforeach()

install(
    DIRECTORY generated/include/
    TYPE INCLUDE
)

configure_file(cmakeConfig.cmake.in "${CMAKE_BINARY_DIR}/qdrvm-cratesConfig.cmake" @ONLY)

install(
    FILES "${CMAKE_BINARY_DIR}/qdrvm-cratesConfig.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/qdrvm-crates/"
)
