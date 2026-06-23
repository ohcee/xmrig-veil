/* XMRig Veil fork */
#include "crypto/rx/RxVeil.h"
#include "base/tools/bswap_64.h"
#include "crypto/randomx/randomx.h"

#include <cstring>

namespace xmrig {

void RxVeil::initJob(const uint8_t *blob, size_t blobSize, size_t nonceOffset,
                     sph_sha256_context &ctxCache, uint64_t (&dsha256)[4],
                     randomx_vm *vm, uint64_t (&tempHash)[8])

{
    sph_sha256_init(&ctxCache);
    sph_sha256(&ctxCache, blob, nonceOffset);
    sha256d(reinterpret_cast<uint8_t*>(dsha256), blob, blobSize);
    randomx_calculate_hash_first(vm, tempHash, dsha256, 32);
}

void RxVeil::hashStep(const uint8_t *blob, size_t blobSize, size_t nonceOffset,
                      const sph_sha256_context &ctxCache, uint64_t (&dsha256)[4],
                      randomx_vm *vm, uint64_t (&tempHash)[8], uint8_t *outHash)
{
    sph_sha256_context ctx;
    std::memcpy(&ctx, &ctxCache, sizeof(ctx));
    sph_sha256(&ctx, blob + nonceOffset, blobSize - nonceOffset);
    sph_sha256_close(&ctx, dsha256);
    sph_sha256_full(reinterpret_cast<uint8_t*>(dsha256), reinterpret_cast<uint8_t*>(dsha256), 32);

    randomx_calculate_hash_next(vm, tempHash, dsha256, 32, outHash);
}

uint64_t RxVeil::difficultyValue(const uint8_t *hash)
{
    return bswap_64(*reinterpret_cast<const uint64_t*>(hash));
}

} // namespace xmrig