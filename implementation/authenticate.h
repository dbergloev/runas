#ifndef RUNAS_AUTHENTICATE_H
#define RUNAS_AUTHENTICATE_H

#define MAX_PASSWORD_LENGTH 50
#define MAX_USERNAME_LENGTH 50

extern const uint32_t AUTH_STDIN;
extern const uint32_t AUTH_PROMPT;

typedef enum {
  AUTH_SUCCESS,
  AUTH_FAILED,
  AUTH_DENIED
} auth_t;

auth_t authenticate(const uid_t target, const uint32_t flags);

#endif // RUNAS_AUTHENTICATE_H
