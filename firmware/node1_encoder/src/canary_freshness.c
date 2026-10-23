#include <string.h>
#include "canary_freshness.h"
#include "blake3.h"

static const uint8_t LEFT_SALT  = 'L';   /* OSU LEFT_SALT  = b"L" */
static const uint8_t RIGHT_SALT = 'R';   /* OSU RIGHT_SALT = b"R" */

/* child = BLAKE3(parent || salt), truncated to 24 bytes (OSU digest(length=24)). */
static void derive_child(uint8_t out[CANARY_TREE_NODE_LEN],
                         const uint8_t *parent, size_t parent_len,
                         uint8_t salt)
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, parent, parent_len);
    blake3_hasher_update(&h, &salt, 1);
    blake3_hasher_finalize(&h, out, CANARY_TREE_NODE_LEN);
    memset(&h, 0, sizeof h);
}

void canary_freshness_derive(uint8_t out[CANARY_FRESHNESS_LEN],
                             const uint8_t tree_seed[CANARY_TREE_SEED_LEN],
                             uint32_t epoch)
{
    uint8_t cur[CANARY_TREE_NODE_LEN];
    uint64_t t = (uint64_t)epoch;   /* zero-extended to the 64-bit tree height */

    /* Level 0: the root is the full-length seed. */
    {
        int bit = (int)((t >> (CANARY_TREE_HEIGHT - 1)) & 1u);
        derive_child(cur, tree_seed, CANARY_TREE_SEED_LEN,
                     bit ? RIGHT_SALT : LEFT_SALT);
    }

    /* Levels 1..63: parent is the 24-byte value from the previous level. */
    for (int level = 1; level < CANARY_TREE_HEIGHT; level++) {
        int bit = (int)((t >> (CANARY_TREE_HEIGHT - 1 - level)) & 1u);
        uint8_t next[CANARY_TREE_NODE_LEN];
        derive_child(next, cur, CANARY_TREE_NODE_LEN,
                     bit ? RIGHT_SALT : LEFT_SALT);
        memcpy(cur, next, sizeof cur);
        memset(next, 0, sizeof next);
    }

    /* CANARY truncation: the locked protocol has only 16 bytes for
     * freshness, so keep the first 16 of the 24-byte OSU leaf value. */
    memcpy(out, cur, CANARY_FRESHNESS_LEN);
    memset(cur, 0, sizeof cur);
}

int canary_freshness_check(const uint8_t received[CANARY_FRESHNESS_LEN],
                           const uint8_t tree_seed[CANARY_TREE_SEED_LEN],
                           uint32_t epoch)
{
    uint8_t expected[CANARY_FRESHNESS_LEN];
    uint8_t diff = 0;

    canary_freshness_derive(expected, tree_seed, epoch);
    for (int i = 0; i < CANARY_FRESHNESS_LEN; i++)
        diff |= (uint8_t)(expected[i] ^ received[i]);
    memset(expected, 0, sizeof expected);
    return diff == 0;
}

/* ---- Replay state ------------------------------------------------------ */

void canary_replay_init(canary_replay_state_t *st)
{
    st->last_epoch = 0;
    st->have_last  = 0;
}

canary_replay_result_t canary_replay_check(const canary_replay_state_t *st,
                                           uint32_t epoch)
{
    if (!st->have_last || epoch > st->last_epoch)
        return CANARY_REPLAY_ACCEPT;
    return CANARY_REPLAY_REJECT;
}

void canary_replay_commit(canary_replay_state_t *st, uint32_t epoch)
{
    st->last_epoch = epoch;
    st->have_last  = 1;
}

canary_replay_result_t canary_replay_accept(canary_replay_state_t *st,
                                            uint32_t epoch)
{
    canary_replay_result_t r = canary_replay_check(st, epoch);
    if (r == CANARY_REPLAY_ACCEPT)
        canary_replay_commit(st, epoch);
    return r;
}
