#ifndef RUNAS_AUTHENTICATE_H
#define RUNAS_AUTHENTICATE_H

typedef enum {
  AUTH_SUCCESS,
  AUTH_FAILED,
  AUTH_DENIED
} auth_t;

auth_t authenticate(const uid_t target, const uint32_t flags);

#endif // RUNAS_AUTHENTICATE_H
