
#include "oatpp-test/UnitTest.hpp"

#include "FullTest.hpp"
#include "FullAsyncTest.hpp"
#include "FullAsyncClientTest.hpp"

#include "oatpp/core/concurrency/SpinLock.hpp"
#include "oatpp/core/base/Environment.hpp"

#include <iostream>

namespace {

class Logger : public oatpp::base::Logger {
private:
  oatpp::concurrency::SpinLock m_lock;
public:

  void log(v_int32 priority, const std::string& tag, const std::string& message) override {
    std::lock_guard<oatpp::concurrency::SpinLock> lock(m_lock);
    std::cout << tag << ":" << message << "\n";
  }

};

void runTests() {

  {

    oatpp::test::mbedtls::FullTest test_virtual(0, 100);
    test_virtual.run();

    oatpp::test::mbedtls::FullTest test_port(8000, 10);
    test_port.run();

  }

  {

    oatpp::test::mbedtls::FullAsyncTest test_virtual(0, 100);
    test_virtual.run();

    oatpp::test::mbedtls::FullAsyncTest test_port(8000, 10);
    test_port.run();

  }

  {

    oatpp::test::mbedtls::FullAsyncClientTest test_virtual(0, 10);
    test_virtual.run(20);

    oatpp::test::mbedtls::FullAsyncClientTest test_port(8000, 10);
    test_port.run(1);

  }

}

}

int main() {

  oatpp::base::Environment::init();
  oatpp::base::Environment::setLogger(new Logger());

  runTests();

  oatpp::base::Environment::setLogger(nullptr);
  oatpp::base::Environment::destroy();

  /* Print how much objects were created during app running, and what have left-probably leaked */
  /* Disable object counting for release builds using '-D OATPP_DISABLE_ENV_OBJECT_COUNTERS' flag for better performance */
  std::cout << "\nEnvironment:\n";
  std::cout << "objectsCount = " << oatpp::base::Environment::getObjectsCount() << "\n";
  std::cout << "objectsCreated = " << oatpp::base::Environment::getObjectsCreated() << "\n\n";

  OATPP_ASSERT(oatpp::base::Environment::getObjectsCount() == 0);

  oatpp::base::Environment::destroy();

  return 0;
}
