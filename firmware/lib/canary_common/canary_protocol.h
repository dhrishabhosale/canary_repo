#ifndef CANARY_PROTOCOL_H
#define CANARY_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------
 * CANARY message format
 *
 * All multi-byte integer fields are little-endian.
 *
 * Wire size:
 *   sender_id  = 1 byte
 *   msg_type   = 1 byte
 *   subtype    = 1 byte
 *   epoch      = 4 bytes
 *   payload    = 4 bytes
 *   freshness  = 16 bytes
 *   signature  = 64 bytes
 *
 * Total = 91 bytes
 * --------------------------------------------------------------------- */

#define CANARY_SIG_LEN 64


/* ---------------------------------------------------------------------
 * Node IDs
 * --------------------------------------------------------------------- */

typedef enum {
    CANARY_NODE_ENCODER   = 1,
    CANARY_NODE_IMU       = 2,
    CANARY_NODE_MOTOR     = 3,
    CANARY_NODE_SECURITY  = 4,
    CANARY_NODE_ATTACKER  = 5,
    CANARY_NODE_GATEWAY   = 6,
} canary_node_id_t;


/* ---------------------------------------------------------------------
 * Message types
 * --------------------------------------------------------------------- */

typedef enum {
    CANARY_MSG_WHEEL_SPEED = 1,
    CANARY_MSG_IMU_DATA    = 2,
    CANARY_MSG_MOTION_CMD  = 3,
    CANARY_MSG_MOTOR_ACK   = 4,
} canary_msg_type_t;


/* ---------------------------------------------------------------------
 * Subtypes
 *
 * WHEEL_SPEED:
 *   0 = Front Left
 *   1 = Front Right
 *   2 = Rear Left
 *   3 = Rear Right
 *
 * IMU_DATA:
 *   0 = Accelerometer X
 *   1 = Accelerometer Y
 *   2 = Accelerometer Z
 *   3 = Gyroscope X
 *   4 = Gyroscope Y
 *   5 = Gyroscope Z
 * --------------------------------------------------------------------- */

typedef enum {
    CANARY_WHEEL_FL = 0,
    CANARY_WHEEL_FR = 1,
    CANARY_WHEEL_RL = 2,
    CANARY_WHEEL_RR = 3,
} canary_wheel_subtype_t;


typedef enum {
    CANARY_IMU_AX = 0,
    CANARY_IMU_AY = 1,
    CANARY_IMU_AZ = 2,
    CANARY_IMU_GX = 3,
    CANARY_IMU_GY = 4,
    CANARY_IMU_GZ = 5,
} canary_imu_subtype_t;


/* ---------------------------------------------------------------------
 * Signed region
 *
 * Everything in this structure is covered by the Ed25519 signature.
 * --------------------------------------------------------------------- */

#pragma pack(push, 1)

typedef struct {
    uint8_t  sender_id;      /* canary_node_id_t */
    uint8_t  msg_type;       /* canary_msg_type_t */
    uint8_t  subtype;        /* sensor/wheel subtype */
    uint32_t epoch;          /* monotonic per-sender counter */
    int32_t  payload;        /* sensor value / command value */
    uint8_t  freshness[16];  /* BLAKE3 hash-tree freshness token */
} canary_signed_region_t;


typedef struct {
    canary_signed_region_t body;
    uint8_t signature[CANARY_SIG_LEN];  /* Ed25519 over body */
} canary_message_t;

#pragma pack(pop)


/* ---------------------------------------------------------------------
 * Size constants
 * --------------------------------------------------------------------- */

#define CANARY_SIGNED_REGION_SIZE sizeof(canary_signed_region_t)
#define CANARY_MESSAGE_SIZE       sizeof(canary_message_t)


#endif /* CANARY_PROTOCOL_H */
