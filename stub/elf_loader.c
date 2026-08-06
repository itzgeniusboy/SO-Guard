/*
 * In-memory ELF64 loader implementation for AArch64 Android shared objects (.so).
 */

#include "elf_loader.h"
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <jni.h>

#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif

typedef jint (*fn_jni_onload)(void*, void*);

void* load_elf_in_memory(const uint8_t *elf_bytes, size_t elf_size, void *vm, void *reserved) {
    if (!elf_bytes || elf_size < sizeof(Elf64_Ehdr)) {
        return NULL;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr*)elf_bytes;

    // Validate ELF Magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return NULL;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr*)(elf_bytes + ehdr->e_phoff);
    uintptr_t min_vaddr = (uintptr_t)-1;
    uintptr_t max_vaddr = 0;
    int pt_load_count = 0;

    // 1. Calculate total virtual memory space needed for PT_LOAD segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            pt_load_count++;
            if (phdrs[i].p_vaddr < min_vaddr) {
                min_vaddr = phdrs[i].p_vaddr;
            }
            if (phdrs[i].p_vaddr + phdrs[i].p_memsz > max_vaddr) {
                max_vaddr = phdrs[i].p_vaddr + phdrs[i].p_memsz;
            }
        }
    }

    if (pt_load_count == 0 || max_vaddr <= min_vaddr) {
        return NULL;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t total_size = (max_vaddr - min_vaddr + page_size - 1) & ~(page_size - 1);

    // 2. Allocate contiguous memory map for image
    uint8_t *mapped_base = (uint8_t*)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped_base == MAP_FAILED) {
        return NULL;
    }

    uintptr_t load_bias = (uintptr_t)mapped_base - min_vaddr;

    // 3. Copy PT_LOAD segments to mapped virtual offsets
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            uint8_t *seg_dst = (uint8_t*)(load_bias + phdrs[i].p_vaddr);
            if (phdrs[i].p_filesz > 0) {
                memcpy(seg_dst, elf_bytes + phdrs[i].p_offset, phdrs[i].p_filesz);
            }
            if (phdrs[i].p_memsz > phdrs[i].p_filesz) {
                memset(seg_dst + phdrs[i].p_filesz, 0, phdrs[i].p_memsz - phdrs[i].p_filesz);
            }
        }
    }

    // 4. Process PT_DYNAMIC section & relocations
    const Elf64_Rela *rela_table = NULL;
    size_t rela_count = 0;
    const Elf64_Sym *sym_table = NULL;
    const char *str_table = NULL;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            const Elf64_Dyn *dyn = (const Elf64_Dyn*)(load_bias + phdrs[i].p_vaddr);
            size_t rela_sz = 0;
            size_t rela_ent = sizeof(Elf64_Rela);

            while (dyn->d_tag != DT_NULL) {
                switch (dyn->d_tag) {
                    case DT_RELA:
                        rela_table = (const Elf64_Rela*)(load_bias + dyn->d_un.d_ptr);
                        break;
                    case DT_RELASZ:
                        rela_sz = dyn->d_un.d_val;
                        break;
                    case DT_RELAENT:
                        if (dyn->d_un.d_val > 0) rela_ent = dyn->d_un.d_val;
                        break;
                    case DT_SYMTAB:
                        sym_table = (const Elf64_Sym*)(load_bias + dyn->d_un.d_ptr);
                        break;
                    case DT_STRTAB:
                        str_table = (const char*)(load_bias + dyn->d_un.d_ptr);
                        break;
                    case DT_JMPREL:
                        // PLT relocations table
                        if (!rela_table) {
                            rela_table = (const Elf64_Rela*)(load_bias + dyn->d_un.d_ptr);
                        }
                        break;
                    case DT_PLTRELSZ:
                        if (rela_sz == 0) rela_sz = dyn->d_un.d_val;
                        break;
                }
                dyn++;
            }

            if (rela_table && rela_sz > 0) {
                rela_count = rela_sz / rela_ent;
            }
            break;
        }
    }

    // Process Relocation Entries
    if (rela_table && rela_count > 0) {
        for (size_t i = 0; i < rela_count; i++) {
            const Elf64_Rela *rela = &rela_table[i];
            uint32_t type = ELF64_R_TYPE(rela->r_info);
            uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
            uint64_t *target_addr = (uint64_t*)(load_bias + rela->r_offset);

            if (type == R_AARCH64_RELATIVE) {
                *target_addr = load_bias + rela->r_addend;
            } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
                if (sym_table && str_table && sym_idx > 0) {
                    const char *sym_name = str_table + sym_table[sym_idx].st_name;
                    void *resolved = dlsym(RTLD_DEFAULT, sym_name);
                    if (resolved) {
                        *target_addr = (uintptr_t)resolved + rela->r_addend;
                    } else if (sym_table[sym_idx].st_value != 0) {
                        *target_addr = load_bias + sym_table[sym_idx].st_value + rela->r_addend;
                    }
                }
            }
        }
    }

    // 5. Apply Page Protections per PT_LOAD segment
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            uintptr_t seg_start = (load_bias + phdrs[i].p_vaddr) & ~(page_size - 1);
            uintptr_t seg_end = (load_bias + phdrs[i].p_vaddr + phdrs[i].p_memsz + page_size - 1) & ~(page_size - 1);
            size_t seg_size = seg_end - seg_start;

            int prot = 0;
            if (phdrs[i].p_flags & PF_R) prot |= PROT_READ;
            if (phdrs[i].p_flags & PF_W) prot |= PROT_WRITE;
            if (phdrs[i].p_flags & PF_X) prot |= PROT_EXEC;

            mprotect((void*)seg_start, seg_size, prot);
        }
    }

    // 6. Search for JNI_OnLoad and invoke if present
    if (sym_table && str_table) {
        for (size_t i = 0; i < 10000; i++) {
            if (sym_table[i].st_name == 0) continue;
            const char *name = str_table + sym_table[i].st_name;
            if (strcmp(name, "JNI_OnLoad") == 0 && sym_table[i].st_value != 0) {
                fn_jni_onload jni_func = (fn_jni_onload)(load_bias + sym_table[i].st_value);
                if (vm) {
                    jni_func(vm, reserved);
                }
                break;
            }
        }
    }

    return (void*)mapped_base;
}
