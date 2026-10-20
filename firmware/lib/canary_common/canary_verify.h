#ifndef CANARY_VERIFY_H
#define CANARY_VERIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "canary_protocol.h"
#include "canary_crypto.h"
#include "canary_freshness.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 4 (Node 1) + 6 (Node 2) + 8 configurable (Node 6) */
#define CANARY_VERIFY_MAX_GATEWAY_STREAMS  8u
#define CANARY_VERIFY_MAX_STREAMS          (4u + 6u + CANARY_VERIFY_MAX_GATEWAY_STREAMS)

typedef enum {
    CANARY_VERIFY_ACCEPT = 0,
    CANARY_VERIFY_REJECT_INVALID_ARG,        /* NULL context or message         */
    CANARY_VERIFY_REJECT_UNTRUSTED_SENDER,   /* Node 5 or any non-trusted node  */
    CANARY_VERIFY_REJECT_UNKNOWN_STREAM,     /* not in the configured allowlist */
    CANARY_VERIFY_REJECT_BAD_SIGNATURE,
    CANARY_VERIFY_REJECT_BAD_FRESHNESS,
    CANARY_VERIFY_REJECT_REPLAY
} canary_verify_result_t;

typedef enum {
    CANARY_VERIFY_CFG_OK = 0,
    CANARY_VERIFY_CFG_INVALID_ARG,
    CANARY_VERIFY_CFG_UNTRUSTED_SENDER,
    CANARY_VERIFY_CFG_STREAM_NOT_ALLOWED,    /* e.g. Node 1 with an IMU subtype */
    CANARY_VERIFY_CFG_DUPLICATE,
    CANARY_VERIFY_CFG_NO_SPACE
} canary_verify_cfg_result_t;

typedef struct {
    bool     configured;
    uint8_t  sender_id;
    uint8_t  msg_type;
    uint8_t  subtype;
    uint8_t  public_key[CANARY_PUBLIC_KEY_LEN];
    uint8_t  tree_seed[CANARY_TREE_SEED_LEN];
    canary_replay_state_t replay;
} canary_verify_stream_t;

typedef struct {
    canary_verify_stream_t streams[CANARY_VERIFY_MAX_STREAMS];
} canary_verify_context_t;

/* Clears all streams and replay state. Safe to call with NULL (no-op). */
void canary_verify_init(canary_verify_context_t *ctx);

/*
 * Installs one stream. Node 1 and Node 2 streams must match the fixed
 * allowlist; Node 6 streams are accepted only if explicitly configured here.
 * Node 5 and any other sender are refused. Duplicate streams are refused.
 * On any failure the context is left unmodified.
 */
canary_verify_cfg_result_t canary_verify_configure_stream(
    canary_verify_context_t *ctx,
    uint8_t sender_id,
    uint8_t msg_type,
    uint8_t subtype,
    const uint8_t public_key[CANARY_PUBLIC_KEY_LEN],
    const uint8_t tree_seed[CANARY_TREE_SEED_LEN]);

/*
 * Verifies msg. Replay state is committed only on CANARY_VERIFY_ACCEPT.
 * The message is never modified.
 */
canary_verify_result_t canary_verify_message(
    canary_verify_context_t *ctx,
    const canary_message_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* CANARY_VERIFY_H */
