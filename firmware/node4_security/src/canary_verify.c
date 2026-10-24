#include "canary_verify.h"
#include <string.h>

static bool is_trusted_sender(uint8_t sender_id)
{
    return sender_id == CANARY_NODE_ENCODER ||
           sender_id == CANARY_NODE_IMU     ||
           sender_id == CANARY_NODE_GATEWAY;
}

/* Fixed allowlist for Node 1 and Node 2. Node 6 is configuration-driven. */
static bool is_allowed_stream(uint8_t sender, uint8_t type, uint8_t sub)
{
    switch (sender) {
    case CANARY_NODE_ENCODER:
        if (type != CANARY_MSG_WHEEL_SPEED) return false;
        return sub == CANARY_WHEEL_FL || sub == CANARY_WHEEL_FR ||
               sub == CANARY_WHEEL_RL || sub == CANARY_WHEEL_RR;
    case CANARY_NODE_IMU:
        if (type != CANARY_MSG_IMU_DATA) return false;
        return sub == CANARY_IMU_AX || sub == CANARY_IMU_AY ||
               sub == CANARY_IMU_AZ || sub == CANARY_IMU_GX ||
               sub == CANARY_IMU_GY || sub == CANARY_IMU_GZ;
    case CANARY_NODE_GATEWAY:
        return true; /* gated by explicit configuration, no semantics invented */
    default:
        return false;
    }
}

/* Linear search; wire values are only compared, never used as indexes. */
static canary_verify_stream_t *find_stream(canary_verify_context_t *ctx,
                                           uint8_t sender, uint8_t type,
                                           uint8_t sub)
{
    for (size_t i = 0; i < CANARY_VERIFY_MAX_STREAMS; i++) {
        canary_verify_stream_t *s = &ctx->streams[i];
        if (s->configured && s->sender_id == sender &&
            s->msg_type == type && s->subtype == sub) {
            return s;
        }
    }
    return NULL;
}

void canary_verify_init(canary_verify_context_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    for (size_t i = 0; i < CANARY_VERIFY_MAX_STREAMS; i++) {
        ctx->streams[i].configured = false;
        canary_replay_init(&ctx->streams[i].replay);
    }
}

canary_verify_cfg_result_t canary_verify_configure_stream(
    canary_verify_context_t *ctx,
    uint8_t sender_id,
    uint8_t msg_type,
    uint8_t subtype,
    const uint8_t public_key[CANARY_PUBLIC_KEY_LEN],
    const uint8_t tree_seed[CANARY_TREE_SEED_LEN])
{
    if (ctx == NULL || public_key == NULL || tree_seed == NULL)
        return CANARY_VERIFY_CFG_INVALID_ARG;
    if (!is_trusted_sender(sender_id))
        return CANARY_VERIFY_CFG_UNTRUSTED_SENDER;
    if (!is_allowed_stream(sender_id, msg_type, subtype))
        return CANARY_VERIFY_CFG_STREAM_NOT_ALLOWED;
    if (find_stream(ctx, sender_id, msg_type, subtype) != NULL)
        return CANARY_VERIFY_CFG_DUPLICATE;

    /* Gateway streams are capped so they cannot consume Node 1/2 slots. */
    size_t gw_count = 0;
    canary_verify_stream_t *slot = NULL;
    for (size_t i = 0; i < CANARY_VERIFY_MAX_STREAMS; i++) {
        canary_verify_stream_t *s = &ctx->streams[i];
        if (s->configured) {
            if (s->sender_id == CANARY_NODE_GATEWAY) gw_count++;
        } else if (slot == NULL) {
            slot = s;
        }
    }
    if (slot == NULL)
        return CANARY_VERIFY_CFG_NO_SPACE;
    if (sender_id == CANARY_NODE_GATEWAY &&
        gw_count >= CANARY_VERIFY_MAX_GATEWAY_STREAMS)
        return CANARY_VERIFY_CFG_NO_SPACE;

    slot->sender_id = sender_id;
    slot->msg_type  = msg_type;
    slot->subtype   = subtype;
    memcpy(slot->public_key, public_key, CANARY_PUBLIC_KEY_LEN);
    memcpy(slot->tree_seed, tree_seed, CANARY_TREE_SEED_LEN);
    canary_replay_init(&slot->replay);
    slot->configured = true; /* set last */
    return CANARY_VERIFY_CFG_OK;
}

canary_verify_result_t canary_verify_message(
    canary_verify_context_t *ctx,
    const canary_message_t *msg)
{
    if (ctx == NULL || msg == NULL)
        return CANARY_VERIFY_REJECT_INVALID_ARG;

    /* Copy wire values once so every check uses the same snapshot. */
    const uint8_t  sender = msg->body.sender_id;
    const uint8_t  type   = msg->body.msg_type;
    const uint8_t  sub    = msg->body.subtype;
    const uint32_t epoch  = msg->body.epoch;

    if (!is_trusted_sender(sender))
        return CANARY_VERIFY_REJECT_UNTRUSTED_SENDER;

    canary_verify_stream_t *s = find_stream(ctx, sender, type, sub);
    if (s == NULL)
        return CANARY_VERIFY_REJECT_UNKNOWN_STREAM;

    if (canary_check_signature(msg, s->public_key) != 1)
        return CANARY_VERIFY_REJECT_BAD_SIGNATURE;

    if (canary_freshness_check(msg->body.freshness, s->tree_seed, epoch) != 1)
        return CANARY_VERIFY_REJECT_BAD_FRESHNESS;

    if (canary_replay_check(&s->replay, epoch) != CANARY_REPLAY_ACCEPT)
        return CANARY_VERIFY_REJECT_REPLAY;

    /* All checks passed: the only place replay state is modified. */
    canary_replay_commit(&s->replay, epoch);
    return CANARY_VERIFY_ACCEPT;
}
