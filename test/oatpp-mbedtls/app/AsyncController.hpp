//
//  AsyncController.hpp
//  web-starter-project
//
//  Created by Leonid on 2/12/18.
//  Copyright © 2018 oatpp. All rights reserved.
//

#ifndef oatpp_test_mbedtls_app_AsyncController_hpp
#define oatpp_test_mbedtls_app_AsyncController_hpp

#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp/core/macro/codegen.hpp"
#include "oatpp/core/macro/component.hpp"

namespace oatpp { namespace test {namespace mbedtls { namespace app {

class AsyncController : public oatpp::web::server::api::ApiController {
private:
  typedef AsyncController __ControllerType;
protected:
  AsyncController(const std::shared_ptr<ObjectMapper>& objectMapper)
    : oatpp::web::server::api::ApiController(objectMapper)
  {}
public:

  static std::shared_ptr<AsyncController> createShared(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)){
    return std::shared_ptr<AsyncController>(new AsyncController(objectMapper));
  }

  /**
   *  Begin ENDPOINTs generation ('ApiController' codegen)
   */
#include OATPP_CODEGEN_BEGIN(ApiController)

  ENDPOINT_ASYNC("GET", "/", Root) {

    ENDPOINT_ASYNC_INIT(Root)

    Action act() override {
      return _return(controller->createResponse(Status::CODE_200, "Hello Async MbedTLS!!!"));
    }

  };

  /**
   *  Finish ENDPOINTs generation ('ApiController' codegen)
   */
#include OATPP_CODEGEN_END(ApiController)

};

}}}}

#endif /* oatpp_test_mbedtls_app_AsyncController_hpp */