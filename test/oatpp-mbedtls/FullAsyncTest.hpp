//
// Created by Leonid  on 2019-05-24.
//

#ifndef OATPP_MBEDTLS_FULLASYNCTEST_HPP
#define OATPP_MBEDTLS_FULLASYNCTEST_HPP


#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace test { namespace mbedtls {

class FullAsyncTest : public oatpp::test::UnitTest {
public:

  FullAsyncTest() : UnitTest("TEST[FullAsyncTest]") {}

  void onRun() override;

};

}}}


#endif //OATPP_MBEDTLS_FULLASYNCTEST_HPP
