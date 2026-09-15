#include <string.h>
#include "canary_crypto.h"
#include "monocypher.h"

void canary_keygen(uint8_t secret_key[CANARY_SECRET_KEY_LEN],
                    uint8_t public_key[CANARY_PUBLIC_KEY_LEN],
                    const uint8_t seed[CANARY_SEED_LEN])
{
    uint8_t seed_copy[CANARY_SEED_LEN];
    memcpy(seed_copy, seed, CANARY_SEED_LEN);
    /* crypto_eddsa_key_pair wipes seed_copy internally for us. */
    crypto_eddsa_key_pair(secret_key, public_key, seed_copy);
}

void canary_sign(canary_message_t *msg,
                  const uint8_t secret_key[CANARY_SECRET_KEY_LEN])
{
    crypto_eddsa_sign(msg->signature,
                       secret_key,
                       (const uint8_t *)&msg->body,
                       CANARY_SIGNED_REGION_SIZE);
}

int canary_check_signature(const canary_message_t *msg,
                            const uint8_t public_key[CANARY_PUBLIC_KEY_LEN])
{
    int bad = crypto_eddsa_check(msg->signature,
                                  public_key,
                                  (const uint8_t *)&msg->body,
                                  CANARY_SIGNED_REGION_SIZE);
    return bad == 0; /* Monocypher returns 0 on success, -1 on failure */
}
