/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *                         Benedikt-Alexander Mokroß <bam@icognize.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#ifndef oatpp_mbedtls_Config_hpp
#define oatpp_mbedtls_Config_hpp

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#include <memory>

namespace oatpp { namespace mbedtls {

/**
 * Wrapper over `mbedtls_ssl_config`.
 */
class Config {
private:

  mbedtls_ssl_config m_config;

  mbedtls_entropy_context m_entropy;
  mbedtls_ctr_drbg_context m_ctr_drbg;
  mbedtls_x509_crt m_srvcert;
  mbedtls_x509_crt m_clientcert;
  mbedtls_x509_crt m_cachain;
  mbedtls_pk_context m_privateKey;

  bool m_throwOnVerificationFailed;

public:

  /**
   * Constructor.
   */
  Config();

  /**
   * Non-virtual destructor.
   */
  ~Config();

  /**
   * Create shared Config.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createShared();

  /**
   * Create default server config.
   * @param serverCertFile - server certificate.
   * @param privateKeyFile - private key.
   * @param pkPassword - optional private key password.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultServerConfigShared(const char* serverCertFile, const char* privateKeyFile, const char* pkPassword = nullptr);

  /**
   * Create default client config.
   * @param throwOnVerificationFailed - throw error on server certificate
   * @param caRootCertFile - path to the CA Root certificate to verificate against
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultClientConfigShared(bool throwOnVerificationFailed = false, const char* caRootCertFile = nullptr);

  /**
   * Create default client config.
   * @param throwOnVerificationFailed - throw error on server certificate
   * @param caRootCert - string buffer containing the CA Root certificate to verify against
   * @param clientCert - string buffer containing the client certificate
   * @param privateKey - string buffer containing the private key
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultClientConfigShared(bool throwOnVerificationFailed, std::string caRootCert, std::string clientCert, std::string privateKey);

  /**
   * Get underlying mbedtls_ssl_config.
   * @return - `mbedtls_ssl_config*`.
   */
  mbedtls_ssl_config* getTLSConfig();

  /**
   * Get entropy.
   * @return - `mbedtls_entropy_context*`
   */
  mbedtls_entropy_context* getEntropy();

  /**
   * Get CTR_DRBG.
   * @return - `mbedtls_ctr_drbg_context*`
   */
  mbedtls_ctr_drbg_context* getCTR_DRBG();

  /**
   * Get server certificate.
   * @return - `mbedtls_x509_crt*`
   */
  mbedtls_x509_crt* getServerCertificate();

  /**
   * Get CA Chain.
   * @return - `mbedtls_x509_crt*`
   */
  mbedtls_x509_crt* getCAChain();

  /**
   * Get private key.
   * @return - `mbedtls_pk_context*`
   */
  mbedtls_pk_context* getPrivateKey();

  /**
   * Returns true if server certificate verification is required
   * @return - `bool`
   */
  bool shouldThrowOnVerificationFailed();

};

}}

#endif // oatpp_mbedtls_Config_hpp
