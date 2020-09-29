
add_library(${OATPP_THIS_MODULE_NAME}
        oatpp-mbedtls/Config.cpp
        oatpp-mbedtls/Config.hpp
        oatpp-mbedtls/Connection.cpp
        oatpp-mbedtls/Connection.hpp
        oatpp-mbedtls/server/ConnectionProvider.cpp
        oatpp-mbedtls/server/ConnectionProvider.hpp
        oatpp-mbedtls/client/ConnectionProvider.cpp
        oatpp-mbedtls/client/ConnectionProvider.hpp
)

set_target_properties(${OATPP_THIS_MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_OATPP_EXTERNAL})
endif()

target_link_oatpp(${OATPP_THIS_MODULE_NAME})

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIR}>
)

target_link_libraries(${OATPP_THIS_MODULE_NAME}
        PRIVATE mbedtls::TLS
        PRIVATE mbedtls::X509
        PRIVATE mbedtls::Crypto
)

if(${OATPP_MBEDTLS_DEBUG} GREATER 0)
    target_compile_definitions(${OATPP_THIS_MODULE_NAME} PUBLIC "OATPP_MBEDTLS_DEBUG=${OATPP_MBEDTLS_DEBUG}")
endif()

#######################################################################################################
## install targets

if(OATPP_INSTALL)
    include("../cmake/module-install.cmake")
endif()
