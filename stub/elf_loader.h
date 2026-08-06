#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * In-memory ELF64 loader for AArch64 Android shared libraries (.so).
 * Parses program headers, maps PT_LOAD segments, resolves dynamic relocations,
 * applies segment page protections, and invokes JNI_OnLoad if present.
 * 
 * @param elf_bytes Buffer containing decrypted and decompressed ELF image
 * @param elf_size Size of elf_bytes buffer
 * @param vm JavaVM pointer received in JNI_OnLoad
 * @param reserved Reserved parameter received in JNI_OnLoad
 * 
 * @return Pointer to mapped image base in memory, or NULL on failure.
 */
void* load_elf_in_memory(const uint8_t *elf_bytes, size_t elf_size, void *vm, void *reserved);

#endif // ELF_LOADER_H
