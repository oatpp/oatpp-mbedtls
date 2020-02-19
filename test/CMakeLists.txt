add_executable(module-tests
        oatpp-mbedtls/tests.cpp
        oatpp-mbedtls/FullTest.cpp
        oatpp-mbedtls/FullTest.hpp
        oatpp-mbedtls/FullAsyncTest.cpp
        oatpp-mbedtls/FullAsyncTest.hpp
        oatpp-mbedtls/FullAsyncClientTest.cpp
        oatpp-mbedtls/FullAsyncClientTest.hpp
        oatpp-mbedtls/app/Controller.hpp
        oatpp-mbedtls/app/AsyncController.hpp
        oatpp-mbedtls/app/Client.hpp
        oatpp-mbedtls/app/DTOs.hpp
)

#################################################################
## define certificates path

add_definitions(
        -DCERT_PEM_PATH="${CMAKE_CURRENT_LIST_DIR}/../utility/cert/test_key.pem"
        -DCERT_CRT_PATH="${CMAKE_CURRENT_LIST_DIR}/../utility/cert/test_cert.crt"
)

#################################################################

set_target_properties(module-tests PROPERTIES
        CXX_STANDARD 11
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

target_include_directories(module-tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(module-tests ${LIB_OATPP_EXTERNAL})
endif()

add_dependencies(module-tests ${OATPP_THIS_MODULE_NAME})

target_link_oatpp(module-tests)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(module-tests
        PRIVATE Threads::Threads
)

target_link_libraries(module-tests
        PRIVATE ${OATPP_THIS_MODULE_NAME}
        PRIVATE mbedtls::TLS
        PRIVATE mbedtls::X509
        PRIVATE mbedtls::Crypto
)

add_test(module-tests module-tests)
