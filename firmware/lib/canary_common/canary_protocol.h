#ifndef CANARY_PROTOCOL_H
#define CANARY_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------
 * CANARY message format (step 1)
 *
 * All multi-byte integer fields are little-endian on the wire, which is
 * native for the ESP32 (Xtensa/RISC-V are both little-endian), so no
 * byte-swapping is needed in firmware. Total wire size: 90 bytes, which
 * fits in a single ESP-NOW packet (250-byte payload limit) with margin
 * to spare for future fields.
 * --------------------------------------------------------------------- */

#define CANARY_SIG_LEN   64   /* Ed25519 (Monocypher EdDSA) signature   */

/* Node IDs. Node 5 (attacker) is deliberately never assigned a key. */
typedef enum {
    CANARY_NODE_ENCODER   = 1,
    CANARY_NODE_IMU       = 2,
    CANARY_NODE_MOTOR     = 3,
    CANARY_NODE_SECURITY  = 4,
    CANARY_NODE_ATTACKER  = 5,
    CANARY_NODE_GATEWAY   = 6,
} canary_node_id_t;

typedef enum {
    CANARY_MSG_WHEEL_SPEED = 1,
    CANARY_MSG_IMU_DATA    = 2,
    CANARY_MSG_MOTION_CMD  = 3,
    CANARY_MSG_MOTOR_ACK   = 4,
} canary_msg_type_t;

/*
 * The "signed region" is everything that goes under the Ed25519
 * signature. Keeping it as its own packed struct means the signing and
 * verification code always hash/sign exactly the same bytes, with no
 * risk of the two sides disagreeing on field order.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  sender_id;      /* canary_node_id_t                        */
    uint8_t  msg_type;       /* canary_msg_type_t                       */
    uint32_t epoch;          /* monotonic per-sender counter            */
    int32_t  payload;        /* sensor value / command value            */
    uint8_t  freshness[16];  /* hash-tree freshness token (step 3)      */
} canary_signed_region_t;

typedef struct {
    canary_signed_region_t body;
    uint8_t signature[CANARY_SIG_LEN];   /* Ed25519 over `body`         */
} canary_message_t;
#pragma pack(pop)

#define CANARY_SIGNED_REGION_SIZE  sizeof(canary_signed_region_t)
#define CANARY_MESSAGE_SIZE        sizeof(canary_message_t)

#endif /* CANARY_PROTOCOL_H */
