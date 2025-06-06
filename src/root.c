#include "root.h"

#if defined(LIBFETCH_TLS_ENABLED)

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32) || defined(_WIN64)
#include <wincrypt.h>
#include <windows.h>
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

bool load_platform_root_certificates(SSL_CTX *ssl_ctx) {
  if (!ssl_ctx)
    return false;

#if defined(_WIN32) || defined(_WIN64)
  HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
  if (!hStore)
    return false;

  PCCERT_CONTEXT pContext = NULL;
  X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
  CERT_ENHKEY_USAGE *enhkey_usage = NULL;
  DWORD enhkey_usage_size = 0;
  bool success = true;

  while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
    const unsigned char *cert_data =
        (const unsigned char *)pContext->pbCertEncoded;
    FILETIME now;
    BYTE key_usage[2];
    DWORD req_size;

    if (!cert_data)
      continue;

    // Check certificate validity period
    GetSystemTimeAsFileTime(&now);
    if (CompareFileTime(&pContext->pCertInfo->NotBefore, &now) > 0 ||
        CompareFileTime(&now, &pContext->pCertInfo->NotAfter) > 0)
      continue;

    // Check key usage - must be able to sign certificates
    if (CertGetIntendedKeyUsage(pContext->dwCertEncodingType,
                                pContext->pCertInfo, key_usage,
                                sizeof(key_usage))) {
      if (!(key_usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))
        continue;
    } else if (GetLastError())
      continue;

    // Check enhanced key usage for server authentication
    if (CertGetEnhancedKeyUsage(pContext, 0, NULL, &req_size)) {
      if (req_size && req_size > enhkey_usage_size) {
        void *tmp = realloc(enhkey_usage, req_size);
        if (!tmp) {
          success = false;
          break;
        }
        enhkey_usage = (CERT_ENHKEY_USAGE *)tmp;
        enhkey_usage_size = req_size;
      }

      if (CertGetEnhancedKeyUsage(pContext, 0, enhkey_usage, &req_size)) {
        if (!enhkey_usage->cUsageIdentifier) {
          if ((HRESULT)GetLastError() != CRYPT_E_NOT_FOUND)
            continue;
        } else {
          bool found_server_auth = false;
          for (DWORD i = 0; i < enhkey_usage->cUsageIdentifier; ++i) {
            if (!strcmp("1.3.6.1.5.5.7.3.1",
                        enhkey_usage->rgpszUsageIdentifier[i])) {
              found_server_auth = true;
              break;
            }
          }
          if (!found_server_auth)
            continue;
        }
      } else
        continue;
    } else
      continue;

    // Convert to X.509 and import
    const unsigned char *cert_ptr = cert_data;
    X509 *x509 = d2i_X509(NULL, &cert_ptr, (long)pContext->cbCertEncoded);
    if (x509) {
      X509_STORE_add_cert(store, x509);
      X509_free(x509);
    }
  }

  free(enhkey_usage);
  if (pContext)
    CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);
  return success;

#elif defined(__APPLE__)
  X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);

  // Load system trust anchor certificates
  CFArrayRef anchor_certs = NULL;
  if (SecTrustCopyAnchorCertificates(&anchor_certs) == errSecSuccess &&
      anchor_certs) {
    CFIndex count = CFArrayGetCount(anchor_certs);
    for (CFIndex i = 0; i < count; i++) {
      SecCertificateRef cert_ref =
          (SecCertificateRef)CFArrayGetValueAtIndex(anchor_certs, i);
      if (!cert_ref)
        continue;

      CFDataRef cert_data = SecCertificateCopyData(cert_ref);
      if (!cert_data)
        continue;

      const unsigned char *cert_bytes = CFDataGetBytePtr(cert_data);
      const unsigned char *cert_ptr = cert_bytes;
      X509 *x509 = d2i_X509(NULL, &cert_ptr, CFDataGetLength(cert_data));

      if (x509) {
        // Validate certificate before importing
        if (X509_cmp_time(X509_get_notBefore(x509), NULL) <= 0 &&
            X509_cmp_time(X509_get_notAfter(x509), NULL) >= 0) {
          int key_usage = X509_get_key_usage(x509);
          if (key_usage == -1 || (key_usage & KU_KEY_CERT_SIGN)) {
            BASIC_CONSTRAINTS *bc =
                X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL);
            if (!bc || bc->ca) {
              X509_STORE_add_cert(store, x509);
            }
            if (bc)
              BASIC_CONSTRAINTS_free(bc);
          }
        }
        X509_free(x509);
      }
      CFRelease(cert_data);
    }
    CFRelease(anchor_certs);
  }

  // Load additional certificates from system keychain
  CFMutableDictionaryRef query =
      CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);

  CFArrayRef cert_data_array = NULL;
  if (SecItemCopyMatching(query, (CFTypeRef *)&cert_data_array) ==
          errSecSuccess &&
      cert_data_array) {
    CFIndex count = CFArrayGetCount(cert_data_array);
    for (CFIndex i = 0; i < count; i++) {
      CFDataRef cert_data =
          (CFDataRef)CFArrayGetValueAtIndex(cert_data_array, i);
      if (!cert_data)
        continue;

      const unsigned char *cert_bytes = CFDataGetBytePtr(cert_data);
      const unsigned char *cert_ptr = cert_bytes;
      X509 *x509 = d2i_X509(NULL, &cert_ptr, CFDataGetLength(cert_data));

      if (x509) {
        // Only check expiry for keychain certificates
        if (X509_cmp_time(X509_get_notBefore(x509), NULL) <= 0 &&
            X509_cmp_time(X509_get_notAfter(x509), NULL) >= 0) {
          X509_STORE_add_cert(store, x509);
        }
        X509_free(x509);
      }
    }
    CFRelease(cert_data_array);
  }
  CFRelease(query);
  return true;

#else
  // Unix/Linux/Android - try common certificate locations (based on Go's
  // approach)
  X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
  bool found_certs = false;

  // Possible certificate files; stop after finding one
  const char *cert_files[] = {
      "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
      "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL 6
      "/etc/ssl/ca-bundle.pem",             // OpenSUSE
      "/etc/pki/tls/cacert.pem",            // OpenELEC
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
      "/etc/ssl/cert.pem",                                 // Alpine Linux
      NULL};

  // Try to load from certificate bundle files
  for (int i = 0; cert_files[i] != NULL; i++) {
    if (SSL_CTX_load_verify_locations(ssl_ctx, cert_files[i], NULL) == 1) {
      found_certs = true;
      break;
    }
  }

  // Possible directories with certificate files; try all
  const char *cert_directories[] = {
      "/etc/ssl/certs",     // SLES10/SLES11
      "/etc/pki/tls/certs", // Fedora/RHEL
#ifdef __ANDROID__
      "/system/etc/security/cacerts",    // Android system roots
      "/data/misc/keychain/certs-added", // User trusted CA folder
#endif
      NULL};

  // Try to load from certificate directories
  for (int i = 0; cert_directories[i] != NULL; i++) {
    if (SSL_CTX_load_verify_locations(ssl_ctx, NULL, cert_directories[i]) ==
        1) {
      found_certs = true;
    }
  }

  // Fallback to OpenSSL default paths if nothing found
  if (!found_certs) {
    found_certs = (SSL_CTX_set_default_verify_paths(ssl_ctx) == 1);
  }

  return found_certs;
#endif
}

#endif /* LIBFETCH_TLS_ENABLED */