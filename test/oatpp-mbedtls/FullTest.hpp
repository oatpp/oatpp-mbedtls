//
// Created by Leonid  on 2019-05-24.
//

#ifndef OATPP_MBEDTLS_FULLTEST_HPP
#define OATPP_MBEDTLS_FULLTEST_HPP

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace test { namespace mbedtls {

class FullTest : public oatpp::test::UnitTest {
public:

  FullTest() : UnitTest("TEST[FullTest]") {}

  void onRun() override;

};

}}}


#endif //OATPP_MBEDTLS_FULLTEST_HPP
