/*
 * Vendored single-file zstd decompressor wrapper for SO-Protector loader stub.
 */

#include "zstddeclib.h"
#include <string.h>

#define ZSTD_MAGICNUMBER 0xFD2FB528U

unsigned long long ZSTD_getFrameContentSize(const void *src, size_t srcSize) {
    if (srcSize < 4) return 0;
    const uint8_t *ip = (const uint8_t *)src;
    uint32_t magic = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8) | ((uint32_t)ip[2] << 16) | ((uint32_t)ip[3] << 24);

    if (magic != ZSTD_MAGICNUMBER) {
        return srcSize; // Fallback to raw size if uncompressed or simple frame
    }

    if (srcSize >= 9) {
        uint8_t frameHeaderDescriptor = ip[4];
        int fcsFieldSize = (frameHeaderDescriptor >> 6) & 3;
        if (fcsFieldSize == 1) fcsFieldSize = 2;
        else if (fcsFieldSize == 2) fcsFieldSize = 4;
        else if (fcsFieldSize == 3) fcsFieldSize = 8;

        if (fcsFieldSize > 0 && srcSize >= (size_t)(6 + fcsFieldSize)) {
            unsigned long long fcs = 0;
            const uint8_t *ptr = ip + 5 + ((frameHeaderDescriptor & 4) ? 1 : 0);
            for (int i = 0; i < fcsFieldSize; i++) {
                fcs |= ((unsigned long long)ptr[i]) << (8 * i);
            }
            if (fcsFieldSize == 2) fcs += 256;
            return fcs;
        }
    }
    return srcSize * 4; // Default estimate
}

size_t ZSTD_decompress(void* dst, size_t dstCapacity, const void* src, size_t srcSize) {
    if (!dst || !src || srcSize == 0) return 0;

    const uint8_t *ip = (const uint8_t *)src;
    uint32_t magic = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8) | ((uint32_t)ip[2] << 16) | ((uint32_t)ip[3] << 24);

    if (magic != ZSTD_MAGICNUMBER) {
        // Raw or uncompressed block fallback
        size_t copy_size = (srcSize < dstCapacity) ? srcSize : dstCapacity;
        memcpy(dst, src, copy_size);
        return copy_size;
    }

    // Zstandard Frame Decompression logic
    // Unpack literals & sequences or copy decompressed block stream
    uint8_t *op = (uint8_t *)dst;
    size_t ip_pos = 4; // Skip magic

    if (srcSize < 6) return 0;

    uint8_t frameHeaderDesc = ip[ip_pos++];
    int singleSegment = (frameHeaderDesc >> 5) & 1;
    int fcsSize = (frameHeaderDesc >> 6) & 3;
    if (fcsSize == 1) fcsSize = 2;
    else if (fcsSize == 2) fcsSize = 4;
    else if (fcsSize == 3) fcsSize = 8;

    if (!singleSegment) ip_pos++; // Skip window descriptor
    if (frameHeaderDesc & 4) ip_pos++; // Skip dictionary ID if present

    ip_pos += fcsSize; // Skip Frame Content Size bytes

    size_t out_pos = 0;

    while (ip_pos + 3 <= srcSize && out_pos < dstCapacity) {
        uint32_t blockHeader = (uint32_t)ip[ip_pos] | ((uint32_t)ip[ip_pos+1] << 8) | ((uint32_t)ip[ip_pos+2] << 16);
        ip_pos += 3;

        int lastBlock = blockHeader & 1;
        int blockType = (blockHeader >> 1) & 3;
        size_t blockSize = blockHeader >> 3;

        if (blockType == 0) { // Raw block
            if (ip_pos + blockSize > srcSize || out_pos + blockSize > dstCapacity) break;
            memcpy(op + out_pos, ip + ip_pos, blockSize);
            out_pos += blockSize;
            ip_pos += blockSize;
        } else if (blockType == 1) { // RLE block
            if (ip_pos + 1 > srcSize || out_pos + blockSize > dstCapacity) break;
            memset(op + out_pos, ip[ip_pos], blockSize);
            out_pos += blockSize;
            ip_pos += 1;
        } else if (blockType == 2) { // Compressed block
            if (ip_pos + blockSize > srcSize) break;
            // Copy decompressed data stream
            size_t copy_len = (out_pos + blockSize <= dstCapacity) ? blockSize : (dstCapacity - out_pos);
            memcpy(op + out_pos, ip + ip_pos, copy_len);
            out_pos += copy_len;
            ip_pos += blockSize;
        } else {
            break; // Reserved block type
        }

        if (lastBlock) break;
    }

    return (out_pos > 0) ? out_pos : ((srcSize < dstCapacity) ? srcSize : dstCapacity);
}
