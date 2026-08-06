#ifndef ZSTDDECLIB_H
#define ZSTDDECLIB_H

#include <stddef.h>
#include <stdint.h>

/**
 * Decompress zstd-compressed payload buffer into destination buffer.
 * 
 * @param dst Output buffer for decompressed data
 * @param dstCapacity Maximum capacity of dst buffer
 * @param src Input compressed zstd buffer
 * @param srcSize Size of src buffer
 * 
 * @return Decompressed size in bytes on success, or 0 on error.
 */
size_t ZSTD_decompress(void* dst, size_t dstCapacity, const void* src, size_t srcSize);

/**
 * Get estimated frame content size from zstd header if specified.
 */
unsigned long long ZSTD_getFrameContentSize(const void *src, size_t srcSize);

#endif // ZSTDDECLIB_H
