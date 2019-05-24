/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
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

#include "Config.hpp"

#include "oatpp/core/base/Environment.hpp"

namespace oatpp { namespace mbedtls {

Config::Config() {

  mbedtls_ssl_config_init(&m_config);

  mbedtls_entropy_init(&m_entropy);
  mbedtls_ctr_drbg_init(&m_ctr_drbg);
  mbedtls_x509_crt_init(&m_srvcert);
  mbedtls_x509_crt_init(&m_cachain);
  mbedtls_pk_init(&m_privateKey);

  auto res = mbedtls_ctr_drbg_seed(&m_ctr_drbg, mbedtls_entropy_func, &m_entropy, nullptr, 0);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::Config()]", "Error. Call to mbedtls_ctr_drbg_seed() failed, return value=%d.", res);
    throw std::runtime_error("[oatpp::mbedtls::Config::Config()]: Error. Call to mbedtls_ctr_drbg_seed() failed.");
  }

}

Config::~Config() {

  mbedtls_ssl_config_free(&m_config);

  mbedtls_entropy_free(&m_entropy);

  mbedtls_ctr_drbg_free(&m_ctr_drbg);
  mbedtls_x509_crt_free(&m_srvcert);
  mbedtls_x509_crt_free(&m_cachain);

  mbedtls_pk_free(&m_privateKey);

}

std::shared_ptr<Config> Config::createShared() {
  return std::make_shared<Config>();
}

std::shared_ptr<Config> Config::createDefaultServerConfigShared(const char* serverCertFile, const char* privateKeyFile, const char* pkPassword) {

  auto result = createShared();

  auto res = mbedtls_x509_crt_parse_file(&result->m_srvcert, serverCertFile);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]", "Error. Can't parse serverCertFile path='%s', return value=%d", serverCertFile, res);
    throw std::runtime_error("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]: Error. Can't parse serverCertFile");
  }

  res = mbedtls_pk_parse_keyfile(&result->m_privateKey, privateKeyFile, pkPassword);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]", "Error. Can't parse privateKeyFile path='%s', return value=%d", privateKeyFile, res);
    throw std::runtime_error("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]: Error. Can't parse privateKeyFile");
  }

  res = mbedtls_ssl_config_defaults(&result->m_config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]", "Error. Call to mbedtls_ssl_config_defaults() failed, return value=%d.", res);
    throw std::runtime_error("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]: Error. Call to mbedtls_ssl_config_defaults() failed.");
  }

  mbedtls_ssl_conf_rng(&result->m_config, mbedtls_ctr_drbg_random, &result->m_ctr_drbg);

  res = mbedtls_ssl_conf_own_cert(&result->m_config, &result->m_srvcert, &result->m_privateKey);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]", "Error. Call to mbedtls_ssl_conf_own_cert() failed, return value=%d.", res);
    throw std::runtime_error("[oatpp::mbedtls::Config::createDefaultServerConfigShared()]: Error. Call to mbedtls_ssl_conf_own_cert() failed.");
  }

  return result;

}

std::shared_ptr<Config> Config::createDefaultClientConfigShared() {

  auto result = createShared();

  auto res = mbedtls_ssl_config_defaults(&result->m_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::Config::createDefaultClientConfigShared()]", "Error. Call to mbedtls_ssl_config_defaults() failed, return value=%d.", res);
    throw std::runtime_error("[oatpp::mbedtls::Config::createDefaultClientConfigShared()]: Error. Call to mbedtls_ssl_config_defaults() failed.");
  }

  mbedtls_ssl_conf_authmode(&result->m_config, MBEDTLS_SSL_VERIFY_NONE);

  mbedtls_ssl_conf_rng(&result->m_config, mbedtls_ctr_drbg_random, &result->m_ctr_drbg);

  return result;

}

mbedtls_ssl_config* Config::getTLSConfig() {
  return &m_config;
}

mbedtls_entropy_context* Config::getEntropy() {
  return &m_entropy;
}

mbedtls_ctr_drbg_context* Config::getCTR_DRBG() {
  return &m_ctr_drbg;
}

mbedtls_x509_crt* Config::getServerCertificate() {
  return &m_srvcert;
}

mbedtls_x509_crt* Config::getCAChain() {
  return &m_cachain;
}

mbedtls_pk_context* Config::getPrivateKey() {
  return &m_privateKey;
}

}}