/* XMRig Veil fork */
#ifndef XMRIG_RX_VEIL_H
#define XMRIG_RX_VEIL_H

#include <cstdint>
#include <cstddef>

class randomx_vm;

extern "C" {
    #include "crypto/ghostrider/sph_sha2.h"
}

namespace xmrig {

class Job;

class RxVeil
{
public:
    static void initJob(const uint8_t *blob,
                        size_t blobSize,
                        size_t nonceOffset,
                        sph_sha256_context &ctxCache,
                        uint64_t (&dsha256)[4],
                        randomx_vm *vm,
                        uint64_t (&tempHash)[8]);

    static void hashStep(const uint8_t *blob,
                         size_t blobSize,
                         size_t nonceOffset,
                         const sph_sha256_context &ctxCache,
                         uint64_t (&dsha256)[4],
                         randomx_vm *vm,
                         uint64_t (&tempHash)[8],
                         uint8_t *outHash);

    static uint64_t difficultyValue(const uint8_t *hash);
};

} // namespace xmrig

#endif