/*
 * CANARY Layer 1 test harness -- host-testable, no ESP32 needed.
 *
 * Proves, with real Monocypher EdDSA operations (not mocked):
 *   1. A legitimate node's signed message verifies correctly.
 *   2. The attacker (no valid key) cannot forge a signature.
 *   3. A tampered message (valid signature, modified payload) is caught.
 *   4. A tampered message (valid signature, modified epoch) is caught --
 *      this is the "replay with bumped epoch" case from the protocol
 *      spec: because epoch is inside the signed region, changing it
 *      invalidates the signature, so this is caught by the crypto check
 *      alone, before freshness logic (step 3) even runs.
 *
 * Run: gcc -I. -I../monocypher-4.0.2/src -O2 -Wall \
 *          test_harness.c canary_crypto.c ../monocypher-4.0.2/src/monocypher.c \
 *          -o test_harness && ./test_harness
 */
#include <stdio.h>
#include <string.h>
#include "canary_protocol.h"
#include "canary_crypto.h"

static void print_result(const char *test_name, int expected_valid, int actual_valid) {
    const char *verdict = (expected_valid == actual_valid) ? "PASS" : "FAIL";
    printf("[%s] %-45s -> signature_valid=%d (expected=%d)\n",
           verdict, test_name, actual_valid, expected_valid);
}

int main(void) {
    /* --- Simulate provisioning: Node 1 gets a real keypair --- */
    uint8_t seed1[CANARY_SEED_LEN] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };
    uint8_t node1_sk[CANARY_SECRET_KEY_LEN];
    uint8_t node1_pk[CANARY_PUBLIC_KEY_LEN];
    canary_keygen(node1_sk, node1_pk, seed1);

    /* Node 6 (gateway) gets a DIFFERENT keypair, used for the "attacker
     * has no valid key" test below -- it stands in for "any key that
     * isn't node1_sk", which is exactly the attacker's situation. */
    uint8_t seed6[CANARY_SEED_LEN] = {
        0x99,0x98,0x97,0x96,0x95,0x94,0x93,0x92,0x91,0x90,0x8f,0x8e,0x8d,0x8c,0x8b,0x8a,
        0x89,0x88,0x87,0x86,0x85,0x84,0x83,0x82,0x81,0x80,0x7f,0x7e,0x7d,0x7c,0x7b,0x7a
    };
    uint8_t node6_sk[CANARY_SECRET_KEY_LEN];
    uint8_t node6_pk[CANARY_PUBLIC_KEY_LEN];
    canary_keygen(node6_sk, node6_pk, seed6);

    printf("=== CANARY Layer 1 Test Harness ===\n\n");

    /* --- Test 1: legitimate message, correctly signed and verified --- */
    canary_message_t msg = {0};
    msg.body.sender_id = CANARY_NODE_ENCODER;
    msg.body.msg_type  = CANARY_MSG_WHEEL_SPEED;
    msg.body.epoch     = 1001;
    msg.body.payload   = 42;  /* e.g. 42 encoder ticks this interval */
    memset(msg.body.freshness, 0, sizeof(msg.body.freshness)); /* step 3 */

    canary_sign(&msg, node1_sk);
    int ok = canary_check_signature(&msg, node1_pk);
    print_result("Legitimate signed message", 1, ok);

    /* --- Test 2: attacker forges a message with the WRONG key --- */
    canary_message_t forged = msg;      /* same content */
    canary_sign(&forged, node6_sk);     /* signed with a key that isn't node1's */
    int forged_ok = canary_check_signature(&forged, node1_pk); /* Node 4 checks vs node1's real pk */
    print_result("Attacker forgery (wrong/no valid key)", 0, forged_ok);

    /* --- Test 3: tampered payload after signing (bit-flip attack) --- */
    canary_message_t tampered_payload = msg;  /* has msg's VALID signature */
    tampered_payload.body.payload = 0;        /* attacker edits payload in flight */
    int tampered_ok = canary_check_signature(&tampered_payload, node1_pk);
    print_result("Tampered payload (signature now stale)", 0, tampered_ok);

    /* --- Test 4: replay with bumped epoch (still no valid new signature) --- */
    canary_message_t bumped_epoch = msg;      /* has msg's VALID signature */
    bumped_epoch.body.epoch = 9999;           /* attacker tries to make it look fresh */
    int bumped_ok = canary_check_signature(&bumped_epoch, node1_pk);
    print_result("Replay with edited epoch (sig now stale)", 0, bumped_ok);

    printf("\nAll four tests demonstrate: only a message signed by the\n");
    printf("actual holder of node1_sk, with its content fully intact,\n");
    printf("passes verification against node1's public key.\n");

    return 0;
}
