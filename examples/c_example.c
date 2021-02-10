#include "fujisaki_ringsig.h"

#include <assert.h>

#define OPAQUE_PTR const struct OpaquePtr

int main(int arc, char** argv) {
    OPAQUE_PTR kp1 = generate_keypair();
    OPAQUE_PTR kp2 = generate_keypair();
    OPAQUE_PTR kp3 = generate_keypair();

    uint8_t pubkey[32];
    uint8_t privkey[64];

    const char* election_id = "someid";
    const size_t nelection_id = sizeof "someid";

    OPAQUE_PTR tag = init_tag(election_id, nelection_id);

    assert(get_pubkey(&kp1, &pubkey));
    assert(tag_add_pubkey(&tag, pubkey));

    assert(get_pubkey(&kp2, &pubkey));
    assert(tag_add_pubkey(&tag, pubkey));

    assert(get_pubkey(&kp3, &pubkey));
    assert(tag_add_pubkey(&tag, pubkey));

    const uint8_t* msg1 = "message 1";
    size_t nmsg1 = sizeof "message 1";
    const uint8_t* msg2 = "message 2";
    size_t nmsg2 = sizeof "message 2";

    uint8_t sig1[1024];
    uint8_t sig2[1024];
    assert(get_privkey(&kp1, &privkey));
    size_t nsig1 = sign(msg1, nmsg1, &tag, privkey, &sig1);
    size_t nsig2 = sign(msg2, nmsg2, &tag, privkey, &sig2);
    assert(nsig1 != 0 && nsig2 != 0);
    // Signatures should be valid
    assert(verify(msg1, nmsg1, &tag, sig1, nsig1));
    assert(verify(msg2, nmsg2, &tag, sig2, nsig2));

    // Can't mix signatures
    assert(!verify(msg1, nmsg1, &tag, sig2, nsig2));

    // But we have been caught double-signing!

    uint8_t revealed_pubkey[32];
    assert(Revealed == do_trace(
                msg1, nmsg1,
                sig1, nsig1,
                msg2, nmsg2,
                sig2, nsig2,
                &tag,
                &revealed_pubkey));

    assert(get_pubkey(&kp1, &pubkey));
    for (size_t i = 0; i < 32; ++i) {
        assert(revealed_pubkey[i] == pubkey[i]);
    }

    free_keypair(kp1);
    free_keypair(kp2);
    free_keypair(kp3);
    free_tag(tag);
    return 0;
}
