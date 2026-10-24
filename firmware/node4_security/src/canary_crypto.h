#ifndef CANARY_CRYPTO_H
#define CANARY_CRYPTO_H

#include <stdint.h>
#include "canary_protocol.h"

#define CANARY_SECRET_KEY_LEN 64   /* Monocypher eddsa secret_key format */
#define CANARY_PUBLIC_KEY_LEN 32
#define CANARY_SEED_LEN       32

/* Generates a keypair from a 32-byte random seed. The seed itself must
 * come from a real CSPRNG at provisioning time -- this function does
 * not generate randomness itself, it only derives keys from it, so the
 * same seed always reproduces the same keypair (useful for deterministic
 * test vectors, and for re-flashing a node without re-provisioning). */
void canary_keygen(uint8_t secret_key[CANARY_SECRET_KEY_LEN],
                    uint8_t public_key[CANARY_PUBLIC_KEY_LEN],
                    const uint8_t seed[CANARY_SEED_LEN]);

/* Signs the message's signed-region in place, filling msg->signature.
 * The caller must have already populated msg->body. */
void canary_sign(canary_message_t *msg,
                  const uint8_t secret_key[CANARY_SECRET_KEY_LEN]);

/* Verifies msg->signature against msg->body using the claimed sender's
 * public key. Returns 1 if valid, 0 if invalid. This does NOT check
 * sender_id legitimacy or freshness -- see canary_verify.c for the full
 * pipeline; this function is the crypto primitive only. */
int canary_check_signature(const canary_message_t *msg,
                            const uint8_t public_key[CANARY_PUBLIC_KEY_LEN]);

#endif /* CANARY_CRYPTO_H */
