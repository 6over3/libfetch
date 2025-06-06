#ifndef LIBFETCH_ROOT_H
#define LIBFETCH_ROOT_H

#if defined(LIBFETCH_TLS_ENABLED)

#include <openssl/ssl.h>
#include <stdbool.h>

/**
 * Load platform-specific root certificates into the SSL context's certificate
 * store.
 *
 * This function loads trusted root certificates from the platform's native
 * certificate store with robust validation:
 * - Windows: System ROOT store with expiry, key usage, and enhanced key usage
 * validation
 * - macOS: System trust anchors and keychain certificates with CA and expiry
 * validation
 * - Unix/Linux: Common certificate bundle files and directories (Debian, RHEL,
 * Alpine, etc.)
 * - Android: System and user certificate stores
 * - Fallback: OpenSSL default certificate paths if platform-specific loading
 * fails
 *
 * @param ssl_ctx The SSL context to load certificates into
 * @return true on success, false on failure
 */
bool load_platform_root_certificates(SSL_CTX *ssl_ctx);

#endif /* LIBFETCH_TLS_ENABLED */

#endif /* LIBFETCH_ROOT_H */