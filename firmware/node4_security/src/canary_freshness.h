#ifndef CANARY_FRESHNESS_H
#define CANARY_FRESHNESS_H

#include <stdint.h>

/* ---------------------------------------------------------------------
 * CANARY hash-tree freshness (adapted from the OSU eCTF 2025 design)
 *
 * OSU construction (design/ectf25_design/encoder.py):
 *   - binary hash tree, height 64, the channel seed is the root
 *   - left_child  = BLAKE3(parent || "L")  (digest truncated to 24 bytes)
 *   - right_child = BLAKE3(parent || "R")  (digest truncated to 24 bytes)
 *   - the timestamp bits select left/right from the root down to the leaf
 *
 * CANARY adaptation:
 *   - the CANARY epoch (uint32_t) is the timestamp, zero-extended to 64 bits
 *     so that the full height-64 OSU walk is performed
 *   - bits are consumed MOST significant first (bit 63 ... bit 0)
 *   - the 24-byte leaf value is the same one OSU produces; CANARY stores
 *     only its FIRST 16 BYTES in freshness[16], because the locked CANARY
 *     protocol reserves exactly 16 bytes for freshness.
 *
 * ASSUMPTIONS TO CHECK AGAINST THE OSU SOURCE (not verified here -- the
 * OSU files were not available to the tool that wrote this code):
 *   (1) MSB-first bit order, (2) 32-byte root seed, (3) the 24-byte
 *   truncated value (not the full 32-byte digest) is fed into the next
 *   level. If OSU differs, only canary_freshness.c's derive function
 *   needs to change.
 *
 * This module has NO Ed25519 code. Hash-tree derivation and replay state
 * are deliberately separate.
 * --------------------------------------------------------------------- */

#define CANARY_FRESHNESS_LEN     16   /* matches canary_signed_region_t.freshness */
#define CANARY_TREE_SEED_LEN     32   /* root seed (per-node secret)              */
#define CANARY_TREE_NODE_LEN     24   /* OSU intermediate/leaf length             */
#define CANARY_TREE_HEIGHT       64   /* OSU HASH_TREE_HEIGHT                     */

/* ---- Hash-tree derivation: epoch -> expected freshness ---------------- */

/* Derives the freshness token for `epoch` from the node's tree seed. */
void canary_freshness_derive(uint8_t out[CANARY_FRESHNESS_LEN],
                             const uint8_t tree_seed[CANARY_TREE_SEED_LEN],
                             uint32_t epoch);

/* Returns 1 if `received` equals the expected token for `epoch`, else 0.
 * Comparison is constant-time. */
int canary_freshness_check(const uint8_t received[CANARY_FRESHNESS_LEN],
                           const uint8_t tree_seed[CANARY_TREE_SEED_LEN],
                           uint32_t epoch);

/* ---- Replay state: strict monotonic epoch ------------------------------ */

typedef struct {
    uint32_t last_epoch;   /* highest accepted epoch */
    uint8_t  have_last;    /* 0 until the first epoch is accepted */
} canary_replay_state_t;

typedef enum {
    CANARY_REPLAY_ACCEPT = 1,   /* epoch > last accepted */
    CANARY_REPLAY_REJECT = 0,   /* epoch <= last accepted (replay / stale) */
} canary_replay_result_t;

void canary_replay_init(canary_replay_state_t *st);

/* Pure check: does NOT change state. Accept iff epoch > last_epoch
 * (or nothing has been accepted yet). */
canary_replay_result_t canary_replay_check(const canary_replay_state_t *st,
                                           uint32_t epoch);

/* Records `epoch` as the new highest accepted epoch. Call only after
 * signature AND freshness have passed and canary_replay_check accepted. */
void canary_replay_commit(canary_replay_state_t *st, uint32_t epoch);

/* Convenience: check, and commit if accepted. */
canary_replay_result_t canary_replay_accept(canary_replay_state_t *st,
                                            uint32_t epoch);

#endif /* CANARY_FRESHNESS_H */
