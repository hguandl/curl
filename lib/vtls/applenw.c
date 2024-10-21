#include "curl_setup.h"

#ifdef USE_APPLENW

#include "urldata.h"
#include "connect.h"
#include "curl_printf.h"
#include "curl_trc.h"

#include <Network/Network.h>
#include <CommonCrypto/CommonDigest.h>

#include "vtls.h"
#include "vtls_int.h"
#include "applenw.h"
#include "cipher_suite.h"
#include "x509asn1.h"

struct nw_ssl_backend_data {
  dispatch_queue_t queue;
  nw_connection_t connection;
  nw_connection_state_t state;
};

/* SPKI headers, copied from sectransp.c */
static const unsigned char rsa4096SpkiHeader[] = {
  0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00};

static const unsigned char rsa2048SpkiHeader[] = {
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00};

static const unsigned char ecDsaSecp256r1SpkiHeader[] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

static const unsigned char ecDsaSecp384r1SpkiHeader[] = {
  0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00};

/* Allow legacy API and type to support macOS 10.14 / iOS 12 */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static void apnw_append_tls_ciphersuite(sec_protocol_options_t options,
                                        uint16_t ciphersuite)
{
  sec_protocol_options_add_tls_ciphersuite(options, ciphersuite);
}

static void apnw_set_min_tls_version(sec_protocol_options_t options,
                                     unsigned char version)
{
  switch(version) {
  case CURL_SSLVERSION_TLSv1_0:
    sec_protocol_options_set_tls_min_version(options, kTLSProtocol1);
    break;
  case CURL_SSLVERSION_TLSv1_1:
    sec_protocol_options_set_tls_min_version(options, kTLSProtocol11);
    break;
  case CURL_SSLVERSION_TLSv1_2:
    sec_protocol_options_set_tls_min_version(options, kTLSProtocol12);
    break;
  case CURL_SSLVERSION_TLSv1_3:
    sec_protocol_options_set_tls_min_version(options, kTLSProtocol13);
    break;
  }
}

static void apnw_set_max_tls_version(sec_protocol_options_t options,
                                     unsigned int version_max)
{
  switch(version_max) {
  case CURL_SSLVERSION_MAX_TLSv1_0:
    sec_protocol_options_set_tls_max_version(options, kTLSProtocol1);
    break;
  case CURL_SSLVERSION_MAX_TLSv1_1:
    sec_protocol_options_set_tls_max_version(options, kTLSProtocol11);
    break;
  case CURL_SSLVERSION_MAX_TLSv1_2:
    sec_protocol_options_set_tls_max_version(options, kTLSProtocol12);
    break;
  case CURL_SSLVERSION_MAX_TLSv1_3:
    sec_protocol_options_set_tls_max_version(options, kTLSProtocol13);
    break;
  }
}

static const char *apnw_get_tls_version_str(sec_protocol_metadata_t metadata)
{
  switch(sec_protocol_metadata_get_negotiated_protocol_version(metadata)) {
  case kTLSProtocol1:
    return "TLSv1.0";
  case kTLSProtocol11:
    return "TLSv1.1";
  case kTLSProtocol12:
    return "TLSv1.2";
  case kTLSProtocol13:
    return "TLSv1.3";
  default:
    return "TLS_UNKNOWN";
  }
}

static int apnw_get_cipher_suite_str(sec_protocol_metadata_t metadata,
                                     char *buf, size_t buf_size)
{
  uint16_t id = sec_protocol_metadata_get_negotiated_ciphersuite(metadata);
  return Curl_cipher_suite_get_str(id, buf, buf_size, TRUE);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static void apnw_set_cipher_list(struct Curl_easy *data, const char *ciphers,
                                 sec_protocol_options_t options)
{
  const char *ptr, *end;
  for(ptr = ciphers; ptr[0] != '\0'; ptr = end) {
    uint16_t id = Curl_cipher_suite_walk_str(&ptr, &end);
    if(id)
      apnw_append_tls_ciphersuite(options, id);
    else
      infof(data, "SSL: unknown cipher in list: \"%.*s\"", (int)(end - ptr),
            ptr);
  }
}

static CURLcode apnw_copy_key_der(struct Curl_easy *data, SecKeyRef key,
                                  unsigned char **der, size_t *der_len)
{
  CURLcode result = CURLE_OK;
  CFDictionaryRef key_attr = SecKeyCopyAttributes(key);
  CFDataRef key_data = SecKeyCopyExternalRepresentation(key, NULL);

  do {
    CFStringRef key_type;
    CFNumberRef key_size;
    int key_bits;

    const unsigned char *spkiHeader = NULL;
    size_t spkiHeaderLength;

    CFIndex key_len;
    const UInt8 *key_ptr;

    if(!key_attr) {
      failf(data, "Failed to parse peer public key");
      result = CURLE_PEER_FAILED_VERIFICATION;
      break;
    }

    key_type = CFDictionaryGetValue(key_attr, kSecAttrKeyType);
    key_size = CFDictionaryGetValue(key_attr, kSecAttrKeySizeInBits);
    CFNumberGetValue(key_size, kCFNumberIntType, &key_bits);

    if(CFEqual(key_type, kSecAttrKeyTypeRSA)) {
      if(key_bits == 4096) {
        spkiHeader = rsa4096SpkiHeader;
        spkiHeaderLength = sizeof(rsa4096SpkiHeader);
      }
      else if(key_bits == 2048) {
        spkiHeader = rsa2048SpkiHeader;
        spkiHeaderLength = sizeof(rsa2048SpkiHeader);
      }
    }
    else if(CFEqual(key_type, kSecAttrKeyTypeECSECPrimeRandom)) {
      if(key_bits == 256) {
        spkiHeader = ecDsaSecp256r1SpkiHeader;
        spkiHeaderLength = sizeof(ecDsaSecp256r1SpkiHeader);
      }
      else if(key_bits == 384) {
        spkiHeader = ecDsaSecp384r1SpkiHeader;
        spkiHeaderLength = sizeof(ecDsaSecp384r1SpkiHeader);
      }
    }

    if(!spkiHeader) {
      failf(data, "Unrecoginized peer public key");
      result = CURLE_PEER_FAILED_VERIFICATION;
      break;
    }

    if(!key_data) {
      failf(data, "Failed to get peer public key data");
      result = CURLE_PEER_FAILED_VERIFICATION;
      break;
    }

    key_len = CFDataGetLength(key_data);
    key_ptr = CFDataGetBytePtr(key_data);

    *der_len = key_len + spkiHeaderLength;
    *der = (unsigned char *)malloc(*der_len);
    if(!*der) {
      failf(data, "Failed to allocate memory for peer public key");
      result = CURLE_OUT_OF_MEMORY;
      break;
    }

    memcpy(*der, spkiHeader, spkiHeaderLength);
    memcpy(*der + spkiHeaderLength, key_ptr, key_len);
  } while(0);

  if(key_attr)
    CFRelease(key_attr);
  if(key_data)
    CFRelease(key_data);

  return result;
}

static bool apnw_pin_peer_key(struct Curl_easy *data, SecTrustRef trust,
                              const char *key_sha256_b64)
{
  CURLcode result = CURLE_OK;
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_VERSION_11_0
  SecKeyRef key = SecTrustCopyKey(trust);
#else
  SecKeyRef key = SecTrustCopyPublicKey(trust);
#endif

  do {
    unsigned char *der;
    size_t der_len;

    if(!key) {
      failf(data, "Failed to get peer public key");
      result = CURLE_PEER_FAILED_VERIFICATION;
      break;
    }

    result = apnw_copy_key_der(data, key, &der, &der_len);
    if(result != CURLE_OK) {
      break;
    }

    result = Curl_pin_peer_pubkey(data, key_sha256_b64, der, der_len);
    free(der);
  } while(0);

  if(key)
    CFRelease(key);

  return result == CURLE_OK;
}

static size_t apnw_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "Network");
}

static bool apnw_false_start(void)
{
  return TRUE;
}

static CURLcode apnw_random(struct Curl_easy *data UNUSED_PARAM,
                            unsigned char *entropy, size_t length)
{
  arc4random_buf(entropy, length);
  return CURLE_OK;
}

static CURLcode apnw_sha256sum(const unsigned char *input, size_t inputlen,
                               unsigned char *sha256sum, size_t sha256sumlen)
{
  assert(sha256sumlen >= CURL_SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(input, (CC_LONG)inputlen, sha256sum);
  return CURLE_OK;
}

static void *apnw_get_backend(const struct ssl_connect_data *connssl)
{
  struct nw_ssl_backend_data *backend = connssl->backend;
  DEBUGASSERT(backend);
  return backend;
}

static void *apnw_get_internals(struct ssl_connect_data *connssl,
                                CURLINFO info UNUSED_PARAM)
{
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);
  return (void *)backend->connection;
}

static CURLcode apnw_get_endpoint(struct Curl_easy *data,
                                  struct Curl_cfilter *cf,
                                  nw_endpoint_t *endpoint)
{
  curl_socket_t socket = Curl_conn_cf_get_socket(cf, data);

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  if(getpeername(socket, (struct sockaddr *)&addr, &addr_len) == -1) {
    failf(data, "Failed to get peer address: %d", errno);
    return CURLE_COULDNT_RESOLVE_HOST;
  }

  *endpoint = nw_endpoint_create_address((struct sockaddr *)&addr);
  if(!*endpoint) {
    failf(data, "Failed to create endpoint");
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static CURLcode apnw_get_parameters(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    nw_parameters_t *parameters)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct ssl_primary_config *pri_config = Curl_ssl_cf_get_primary_config(cf);
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  *parameters = nw_parameters_create_secure_tcp(
    ^(nw_protocol_options_t tls_options) {
      sec_protocol_options_t sec_options =
        nw_tls_copy_sec_protocol_options(tls_options);

      size_t i;
      for(i = 0; i < connssl->alpn->count; ++i) {
        sec_protocol_options_add_tls_application_protocol(
          sec_options, connssl->alpn->entries[i]);
      }

      if(pri_config->cipher_list13) {
        apnw_set_cipher_list(data, pri_config->cipher_list13, sec_options);
      }

      if(pri_config->cipher_list) {
        apnw_set_cipher_list(data, pri_config->cipher_list, sec_options);
      }

      apnw_set_min_tls_version(sec_options, pri_config->version);

      apnw_set_max_tls_version(sec_options, pri_config->version_max);

      sec_protocol_options_set_tls_server_name(sec_options, connssl->peer.sni);

      sec_protocol_options_set_tls_false_start_enabled(sec_options,
                                                       ssl_config->falsestart);

      sec_protocol_options_set_verify_block(
        sec_options,
        ^(sec_protocol_metadata_t metadata, sec_trust_t trust_ref,
          sec_protocol_verify_complete_t complete) {
          SecTrustRef trust = sec_trust_copy_ref(trust_ref);

          (void)metadata;

          if(pri_config->pinned_key)
            if(!apnw_pin_peer_key(data, trust, pri_config->pinned_key)) {
              failf(data, "Failed to pin peer public key");
              complete(false);
              sec_release(trust);
              return;
            }

          if(SecTrustEvaluateWithError(trust, NULL))
            complete(true);
          else {
            failf(data, "Failed to verify peer certificate");
            complete(!pri_config->verifypeer);
          }

          sec_release(trust);
        },
        backend->queue);

      nw_release(sec_options);
    },
    NW_PARAMETERS_DEFAULT_CONFIGURATION);
  if(!parameters) {
    failf(data, "Failed to create parameters");
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

static dispatch_time_t apnw_get_timeout(struct Curl_easy *data)
{
  timediff_t ms = Curl_timeleft(data, NULL, TRUE);
  return dispatch_time(DISPATCH_TIME_NOW, ms * NSEC_PER_MSEC);
}

static void apnw_connect_ready(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);
  nw_connection_t conn = backend->connection;

  char *desc;
  nw_protocol_definition_t tls = nw_protocol_copy_tls_definition();
  nw_protocol_metadata_t tls_meta;
  sec_protocol_metadata_t sec_meta;
  const char *tls_str;
  char cipher_str[64];
  const char *alpn;
  __block int cert_i = 0;

  desc = nw_connection_copy_description(conn);
  infof(data, "%s", desc);
  free(desc);

  tls_meta = nw_connection_copy_protocol_metadata(conn, tls);
  sec_meta = nw_tls_copy_sec_protocol_metadata(tls_meta);

  tls_str = apnw_get_tls_version_str(sec_meta);
  apnw_get_cipher_suite_str(sec_meta, cipher_str, 64);
  infof(data, "SSL connection using %s / %s", tls_str, cipher_str);

  alpn = sec_protocol_metadata_get_negotiated_protocol(sec_meta);
  Curl_alpn_set_negotiated(cf, data, connssl, (const unsigned char *)alpn,
                           strlen(alpn));

  sec_protocol_metadata_access_peer_certificate_chain(
    sec_meta, ^(sec_certificate_t cert_ref) {
      SecCertificateRef cert = sec_certificate_copy_ref(cert_ref);
      CFStringRef sub = SecCertificateCopyLongDescription(NULL, cert, NULL);
      const char *str = CFStringGetCStringPtr(sub, kCFStringEncodingUTF8);

      if(str)
        infof(data, "Server certificate: %s", str);
      if(sub)
        CFRelease(sub);

      if(ssl_config->certinfo) {
        do {
          CURLcode result;
          const char *beg;
          const char *end;
          CFDataRef der = SecCertificateCopyData(cert);

          if(!der) {
            infof(data, "Failed to get certificate data");
            break;
          }

          beg = (const char *)CFDataGetBytePtr(der);
          end = beg + CFDataGetLength(der);

          result = Curl_extract_certinfo(data, cert_i, beg, end);
          CFRelease(der);

          if(result != CURLE_OK) {
            infof(data, "Failed to extract certificate information");
            break;
          }

          ++cert_i;
        } while(0);
      }

      CFRelease(cert);
    });

  nw_release(tls);
  nw_release(tls_meta);
  nw_release(sec_meta);

  connssl->state = ssl_connection_complete;
}

static CURLcode apnw_connect_common(struct Curl_cfilter *cf,
                                    struct Curl_easy *data, bool nonblocking)
{
  CURLcode result;
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  nw_endpoint_t endpoint;
  nw_parameters_t parameters;
  dispatch_group_t group = dispatch_group_create();

  result = apnw_get_endpoint(data, cf, &endpoint);
  if(result != CURLE_OK) {
    return result;
  }

  backend->queue = dispatch_queue_create("curl.vtls.applenw", NULL);

  result = apnw_get_parameters(cf, data, &parameters);
  if(result != CURLE_OK) {
    nw_release(endpoint);
    return result;
  }

  backend->connection = nw_connection_create(endpoint, parameters);
  nw_release(endpoint);
  nw_release(parameters);

  if(!backend->connection) {
    failf(data, "Failed to create connection");
    return CURLE_FAILED_INIT;
  }

  nw_connection_set_queue(backend->connection, backend->queue);

  nw_retain(backend->connection);
  nw_connection_set_state_changed_handler(
    backend->connection, ^(nw_connection_state_t state, nw_error_t error) {
      if(error) {
        failf(data, "Failed to connect: %d", nw_error_get_error_code(error));
      }

      if(state == nw_connection_state_waiting) {
        DEBUGF(infof(data, "CONN: waiting for a usable network"));
      }
      else if(state == nw_connection_state_failed) {
        DEBUGF(infof(data, "CONN: irrecoverably closed or failed"));
      }
      else if(state == nw_connection_state_ready) {
        DEBUGF(infof(data, "CONN: ready to send and receive data"));
        apnw_connect_ready(cf, data);
      }
      else if(state == nw_connection_state_cancelled) {
        DEBUGF(infof(data, "CONN: cancelled by the caller"));
        nw_release(backend->connection);
      }

      backend->state = state;

      if(!nonblocking && (error || state == nw_connection_state_ready))
        dispatch_group_leave(group);
    });

  nw_connection_start(backend->connection);

  if(!nonblocking) {
    dispatch_group_enter(group);
    dispatch_group_wait(group, apnw_get_timeout(data));
  }

  dispatch_release(group);
  return CURLE_OK;
}

static CURLcode apnw_connect_blocking(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  CURLcode result;
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  result = apnw_connect_common(cf, data, FALSE);
  if(result != CURLE_OK)
    return result;

  if(backend->state != nw_connection_state_ready)
    return CURLE_SSL_CONNECT_ERROR;

  return CURLE_OK;
}

static CURLcode apnw_connect_nonblocking(struct Curl_cfilter *cf,
                                         struct Curl_easy *data, bool *done)
{
  CURLcode result;
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  if(!backend->connection) {
    result = apnw_connect_common(cf, data, TRUE);
    if(result != CURLE_OK)
      return result;
  }

  switch(backend->state) {
  case nw_connection_state_waiting:
  case nw_connection_state_failed:
  case nw_connection_state_cancelled:
    return CURLE_SSL_CONNECT_ERROR;
  case nw_connection_state_ready:
    *done = TRUE;
    break;
  default:
    break;
  }

  return CURLE_OK;
}

static void apnw_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  DEBUGF(infof(data, "Closing APNW connection"));

  if(backend->connection) {
    nw_release(backend->connection);
    backend->connection = NULL;
  }

  if(backend->queue) {
    dispatch_release(backend->queue);
    backend->queue = NULL;
  }
}

static ssize_t apnw_recv_plain(struct Curl_cfilter *cf, struct Curl_easy *data,
                               char *buf, size_t len, CURLcode *code)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  dispatch_group_t group = dispatch_group_create();
  __block size_t total_size = 0;

  dispatch_group_enter(group);
  nw_connection_receive(
    backend->connection, 1, (uint32_t)len,
    ^(dispatch_data_t content, nw_content_context_t context, bool is_complete,
      nw_error_t error) {
      if(error) {
        failf(data, "Failed to receive data: %d (%d)",
              nw_error_get_error_domain(error),
              nw_error_get_error_code(error));
        *code = CURLE_RECV_ERROR;
        dispatch_group_leave(group);
        return;
      }
      *code = CURLE_OK;

      if(!context || !content) {
        CURL_TRC_CF(data, cf, "Received no content");
        dispatch_group_leave(group);
        return;
      }

      dispatch_data_apply(content, ^bool(dispatch_data_t region UNUSED_PARAM,
                                         size_t offset UNUSED_PARAM,
                                         const void *buffer, size_t size) {
        if(total_size + size <= len) {
          memcpy(buf + total_size, buffer, size);
          total_size += size;
          return true;
        }
        else {
          infof(data, "Received more data than buffer size: %zu > %zu",
                total_size + size, len);
          memcpy(buf + total_size, buffer, len - total_size);
          total_size = len;
          return false;
        }
      });

      if(is_complete || nw_content_context_get_is_final(context)) {
        CURL_TRC_CF(data, cf, "Received complete content");
      }

      dispatch_group_leave(group);
    });

  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
  dispatch_release(group);

  return total_size;
}

static ssize_t apnw_send_plain(struct Curl_cfilter *cf, struct Curl_easy *data,
                               const void *mem, size_t len, CURLcode *code)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  dispatch_data_t content;
  dispatch_group_t group = dispatch_group_create();

  content = dispatch_data_create(mem, len, backend->queue,
                                 DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  dispatch_group_enter(group);

  nw_connection_send(backend->connection, content,
                     NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false,
                     ^(nw_error_t error) {
                       if(error) {
                         failf(data, "Failed to send data: %d (%d)",
                               nw_error_get_error_domain(error),
                               nw_error_get_error_code(error));
                         *code = CURLE_SEND_ERROR;
                       }
                       else {
                         *code = CURLE_OK;
                       }
                       dispatch_group_leave(group);
                     });

  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
  dispatch_release(group);

  return len;
}

static CURLcode apnw_shutdown(struct Curl_cfilter *cf, struct Curl_easy *data,
                              bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct nw_ssl_backend_data *backend = apnw_get_backend(connssl);

  if(!backend->connection || backend->state == nw_connection_state_cancelled) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(backend->state == nw_connection_state_failed) {
    return CURLE_SSL_SHUTDOWN_FAILED;
  }

  if(send_shutdown && backend->connection) {
    *done = FALSE;
    nw_connection_send(backend->connection, NULL,
                       NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                       ^(nw_error_t error) {
                         if(error) {
                           failf(data, "Failed to send close notify: %d (%d)",
                                 nw_error_get_error_domain(error),
                                 nw_error_get_error_code(error));
                           backend->state = nw_connection_state_failed;
                         }
                       });
    return CURLE_OK;
  }

  if(backend->connection) {
    nw_connection_cancel(backend->connection);
  }

  return CURLE_OK;
}

const struct Curl_ssl Curl_ssl_applenw = {
  {CURLSSLBACKEND_APPLENETWORK, "apple-network"}, /* info */

  SSLSUPP_CERTINFO | SSLSUPP_PINNEDPUBKEY | SSLSUPP_HTTPS_PROXY |
    SSLSUPP_CIPHER_LIST | SSLSUPP_TLS13_CIPHERSUITES,

  sizeof(struct nw_ssl_backend_data),

  Curl_none_init,                /* init */
  Curl_none_cleanup,             /* cleanup */
  apnw_version,                  /* version */
  Curl_none_check_cxn,           /* check_cxn */
  apnw_shutdown,                 /* shutdown */
  Curl_none_data_pending,        /* data_pending */
  apnw_random,                   /* random */
  Curl_none_cert_status_request, /* cert_status_request */
  apnw_connect_blocking,         /* connect */
  apnw_connect_nonblocking,      /* connect_nonblocking */
  Curl_ssl_adjust_pollset,       /* adjust_pollset */
  apnw_get_internals,            /* get_internals */
  apnw_close,                    /* close_one */
  Curl_none_close_all,           /* close_all */
  Curl_none_set_engine,          /* set_engine */
  Curl_none_set_engine_default,  /* set_engine_default */
  Curl_none_engines_list,        /* engines_list */
  apnw_false_start,              /* false_start */
  apnw_sha256sum,                /* sha256sum */
  NULL,                          /* associate_connection */
  NULL,                          /* disassociate_connection */
  apnw_recv_plain,               /* recv decrypted data */
  apnw_send_plain,               /* send data to encrypt */
  NULL,                          /* get_channel_binding */
};

#endif /* USE_APPLENW */
