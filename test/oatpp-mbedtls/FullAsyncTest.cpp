//
// Created by Leonid  on 2019-05-24.
//

#include "FullAsyncTest.hpp"

#include "app/AsyncController.hpp"

#include "oatpp-mbedtls/client/ConnectionProvider.hpp"
#include "oatpp-mbedtls/server/ConnectionProvider.hpp"

#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include "oatpp/web/server/AsyncHttpConnectionHandler.hpp"

#include "oatpp/network/server/SimpleTCPConnectionProvider.hpp"
#include "oatpp/network/client/SimpleTCPConnectionProvider.hpp"

#include "oatpp/network/virtual_/client/ConnectionProvider.hpp"
#include "oatpp/network/virtual_/server/ConnectionProvider.hpp"
#include "oatpp/network/virtual_/Interface.hpp"

#include "oatpp-test/web/ClientServerTestRunner.hpp"

#include "oatpp/core/macro/component.hpp"

namespace oatpp { namespace test { namespace mbedtls {

namespace {

//#define OATPP_TEST_USE_PORT 8443

class TestComponent {
public:

  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::async::Executor>, executor)([] {
    return std::make_shared<oatpp::async::Executor>(4, 2);
  }());

  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::virtual_::Interface>, virtualInterface)([] {
    return oatpp::network::virtual_::Interface::createShared("virtualhost");
  }());

  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>, serverConnectionProvider)([] {

#ifdef OATPP_TEST_USE_PORT
    auto streamProvider = oatpp::network::server::SimpleTCPConnectionProvider::createShared(OATPP_TEST_USE_PORT);
#else
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::virtual_::Interface>, interface);
    auto streamProvider = oatpp::network::virtual_::server::ConnectionProvider::createShared(interface);
#endif

    OATPP_LOGD("oatpp::libressl::Config", "pem='%s'", CERT_PEM_PATH);
    OATPP_LOGD("oatpp::libressl::Config", "crt='%s'", CERT_CRT_PATH);

    auto config = oatpp::mbedtls::Config::createDefaultServerConfigShared(CERT_CRT_PATH, CERT_PEM_PATH);

    return oatpp::mbedtls::server::ConnectionProvider::createShared(config, streamProvider);

  }());

  /**
   *  Create Router component
   */
  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, httpRouter)([] {
    return oatpp::web::server::HttpRouter::createShared();
  }());

  /**
   *  Create ConnectionHandler component which uses Router component to route requests
   */
  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::server::ConnectionHandler>, serverConnectionHandler)([] {
    OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router); // get Router component
    OATPP_COMPONENT(std::shared_ptr<oatpp::async::Executor>, executor); // get Executor
    return oatpp::web::server::AsyncHttpConnectionHandler::createShared(router, executor);
  }());

  /**
   *  Create ObjectMapper component to serialize/deserialize DTOs in Contoller's API
   */
  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::data::mapping::ObjectMapper>, apiObjectMapper)([] {
    return oatpp::parser::json::mapping::ObjectMapper::createShared();
  }());

  OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::network::ClientConnectionProvider>, clientConnectionProvider)([this] {

#ifdef OATPP_TEST_USE_PORT
    auto streamProvider = oatpp::network::client::SimpleTCPConnectionProvider::createShared("127.0.0.1", OATPP_TEST_USE_PORT);
#else
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::virtual_::Interface>, interface);
    auto streamProvider = oatpp::network::virtual_::client::ConnectionProvider::createShared(interface);
#endif

    auto config = oatpp::mbedtls::Config::createDefaultClientConfigShared();

    return oatpp::mbedtls::client::ConnectionProvider::createShared(config, streamProvider);

  }());

};

}

void FullAsyncTest::onRun() {

  TestComponent component;

  oatpp::test::web::ClientServerTestRunner runner;

  runner.addController(app::AsyncController::createShared());

  runner.run([] {


    std::this_thread::sleep_for(std::chrono::minutes(10));

  }, std::chrono::minutes(10));

}

}}}