#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include "kallsyms_in_memory.h"

#define KSYM_NAME_LEN 128
#define KSYM_TYPE_LEN 32

#define KSYM_TYPE_FUNC 0
#define KSYM_TYPE_DATA 1

#define KSYM_TYPE_TABLE_PRESENT 0x01

#define KSYM_TYPE_MASK 0x0f
#define KSYM_TYPE_SHIFT 4

#define KSYM_NAME_OFFSET_MASK 0x0fffffff
#define KSYM_NAME_OFFSET_SHIFT 8

#define KSYM_NAME_OFFSET_EXTENDED 0x00000000
#define KSYM_NAME_OFFSET_MASK_EXTENDED 0x00ffffff

#define KSYM_NAME_OFFSET_MAX 0x0fffffff

#define KSYM_NAME_UNKNOWN "<unknown>"

#define KSYM_VERBOSE_LEVEL 0

struct _kallsyms {
    uint8_t *buf;
    size_t len;
    uint8_t *symtab_start;
    uint8_t *symtab_end;
    uint8_t *strtab_start;
    uint8_t *strtab_end;
    uint8_t *type_start;
    uint8_t *type_end;
    uint8_t *name_start;
    uint8_t *name_end;
    bool type_table_present;
};

static uint64_t kallsyms_in_memory_swap(uint64_t val)
{
    return ((val & 0x00000000000000ffULL) << 56) |
           ((val & 0x000000000000ff00ULL) << 40) |
           ((val & 0x0000000000ff0000ULL) << 24) |
           ((val & 0x00000000ff000000ULL) << 8) |
           ((val & 0x000000ff00000000ULL) >> 8) |
           ((val & 0x0000ff0000000000ULL) >> 24) |
           ((val & 0x00ff000000000000ULL) >> 40) |
           ((val & 0xff00000000000000ULL) >> 56);
}

static uint64_t kallsyms_in_memory_read_u64(uint8_t *buf, size_t len, size_t offset)
{
    uint64_t val = 0;
    if (offset + sizeof(val) <= len) {
        memcpy(&val, buf + offset, sizeof(val));
        val = le64toh(val);
    }
    return val;
}

static uint32_t kallsyms_in_memory_read_u32(uint8_t *buf, size_t len, size_t offset)
{
    uint32_t val = 0;
    if (offset + sizeof(val) <= len) {
        memcpy(&val, buf + offset, sizeof(val));
        val = le32toh(val);
    }
    return val;
}

static uint16_t kallsyms_in_memory_read_u16(uint8_t *buf, size_t len, size_t offset)
{
    uint16_t val = 0;
    if (offset + sizeof(val) <= len) {
        memcpy(&val, buf + offset, sizeof(val));
        val = le16toh(val);
    }
    return val;
}

static uint8_t kallsyms_in_memory_read_u8(uint8_t *buf, size_t len, size_t offset)
{
    uint8_t val = 0;
    if (offset + sizeof(val) <= len) {
        memcpy(&val, buf + offset, sizeof(val));
    }
    return val;
}

static bool kallsyms_in_memory_is_type_table_present(uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t val = kallsyms_in_memory_read_u32(ptr, len, 0);
        if ((val & KSYM_TYPE_TABLE_PRESENT) != 0) {
            return true;
        }
        ptr += sizeof(uint32_t);
    }
    return false;
}

static uint8_t *kallsyms_in_memory_find_symtab(uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t val = kallsyms_in_memory_read_u32(ptr, len, 0);
        if ((val & KSYM_TYPE_TABLE_PRESENT) == 0) {
            return ptr;
        }
        ptr += sizeof(uint32_t);
    }
    return NULL;
}

static uint8_t *kallsyms_in_memory_find_strtab(uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t val = kallsyms_in_memory_read_u32(ptr, len, 0);
        if ((val & KSYM_TYPE_TABLE_PRESENT) == 0) {
            uint32_t size = (val >> KSYM_TYPE_SHIFT) & KSYM_NAME_OFFSET_MASK;
            if (size > 0 && ptr + size <= end) {
                return ptr + size;
            }
        }
        ptr += sizeof(uint32_t);
    }
    return NULL;
}

static uint8_t *kallsyms_in_memory_find_type_table(uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t val = kallsyms_in_memory_read_u32(ptr, len, 0);
        if ((val & KSYM_TYPE_TABLE_PRESENT) != 0) {
            uint32_t size = (val >> KSYM_TYPE_SHIFT) & KSYM_NAME_OFFSET_MASK;
            if (size > 0 && ptr + size <= end) {
                return ptr + size;
            }
        }
        ptr += sizeof(uint32_t);
    }
    return NULL;
}

static uint8_t *kallsyms_in_memory_find_name_table(uint8_t *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = buf + len;
    while (ptr + sizeof(uint32_t) <= end) {
        uint32_t val = kallsyms_in_memory_read_u32(ptr, len, 0);
        if ((val & KSYM_TYPE_TABLE_PRESENT) == 0) {
            uint32_t size = (val >> KSYM_NAME_OFFSET_SHIFT) & KSYM_NAME_OFFSET_MASK;
            if (size == KSYM_NAME_OFFSET_EXTENDED) {
                size = kallsyms_in_memory_read_u32(ptr, len, sizeof(uint32_t));
                size &= KSYM_NAME_OFFSET_MASK_EXTENDED;
                size += sizeof(uint32_t);
            }
            if (size > 0 && ptr + size <= end) {
                return ptr + sizeof(uint32_t);
            }
        }
        ptr += sizeof(uint32_t);
    }
    return NULL;
}

static bool kallsyms_in_memory_is_address_in_symtab(struct _kallsyms *ksyms, uint8_t *addr)
{
    return (addr >= ksyms->symtab_start && addr < ksyms->symtab_end);
}

static bool kallsyms_in_memory_is_address_in_strtab(struct _kallsyms *ksyms, uint8_t *addr)
{
    return (addr >= ksyms->strtab_start && addr < ksyms->strtab_end);
}

static bool kallsyms_in_memory_is_address_in_type_table(struct _kallsyms *ksyms, uint8_t *addr)
{
    return (ksyms->type_table_present && addr >= ksyms->type_start && addr < ksyms->type_end);
}

static bool kallsyms_in_memory_is_address_in_name_table(struct _kallsyms *ksyms, uint8_t *addr)
{
    return (addr >= ksyms->name_start && addr < ksyms->name_end);
}

static uint8_t *kallsyms_in_memory_expand_symbol(struct _kallsyms *ksyms, uint8_t *sym, char *buf, size_t buflen)
{
    uint8_t *ptr = sym;
    uint8_t *end = ksyms->strtab_end;
    size_t len = 0;
    while (ptr < end && len < buflen - 1) {
        char c = kallsyms_in_memory_read_u8(ptr, ksyms->len, 0);
        if (c == '\0') {
            break;
        }
        buf[len++] = c;
        ptr++;
    }
    buf[len] = '\0';
    return ptr;
}

static uint8_t *kallsyms_in_memory_lookup_name(struct _kallsyms *ksyms, const char *name, uint8_t **type, uint8_t **addr)
{
    uint8_t *ptr = ksyms->symtab_start;
    uint8_t *end = ksyms->symtab_end;
    while (ptr + sizeof(uint64_t) <= end) {
        uint64_t val = kallsyms_in_memory_read_u64(ptr, ksyms->len, 0);
        uint8_t *sym = (uint8_t *)(val & ~0xffffffffULL);
        uint8_t *off = (uint8_t *)(val & 0xffffffffULL);
        char buf[KSYM_NAME_LEN];
        kallsyms_in_memory_expand_symbol(ksyms, sym, buf, sizeof(buf));
        if (strcmp(buf, name) == 0) {
            if (type != NULL) {
                *type = ksyms->type_start + (off - ksyms->symtab_start);
            }
            if (addr != NULL) {
                *addr = ksyms->name_start + kallsyms_in_memory_read_u32(off, ksyms->len, 0);
            }
            return sym;
        }
        ptr += sizeof(uint64_t);
    }
    return NULL;
}

static uint8_t *kallsyms_in_memory_lookup_names(struct _kallsyms *ksyms, const char *name, uint8_t **type, uint8_t **addr, size_t *count)
{
    uint8_t *ptr = ksyms->symtab_start;
    uint8_t *end = ksyms->symtab_end;
    size_t num_matches = 0;
    while (ptr + sizeof(uint64_t) <= end) {
        uint64_t val = kallsyms_in_memory_read_u64(ptr, ksyms->len, 0);
        uint8_t *sym = (uint8_t *)(val & ~0xffffffffULL);
        uint8_t *off = (uint8_t *)(val & 0xffffffffULL);
        char buf[KSYM_NAME_LEN];
        kallsyms_in_memory_expand_symbol(ksyms, sym, buf, sizeof(buf));
        if (strcmp(buf, name) == 0) {
            if (type != NULL) {
                type[num_matches] = ksyms->type_start + (off - ksyms->symtab_start);
            }
            if (addr != NULL) {
                addr[num_matches] = ksyms->name_start + kallsyms_in_memory_read_u32(off, ksyms->len, 0);
            }
            num_matches++;
        }
        ptr += sizeof(uint64_t);
    }
    if (count != NULL) {
        *count = num_matches;
    }
    return (num_matches > 0) ? ksyms->symtab_start : NULL;
}

static uint8_t *kallsyms_in_memory_lookup_address(struct _kallsyms *ksyms, uint8_t *addr, char *buf, size_t buflen)
{
    uint8_t *ptr = ksyms->symtab_start;
    uint8_t *end = ksyms->symtab_end;
    while (ptr + sizeof(uint64_t) <= end) {
        uint64_t val = kallsyms_in_memory_read_u64(ptr, ksyms->len, 0);
        uint8_t *sym = (uint8_t *)(val & ~0xffffffffULL);
        uint8_t *off = (uint8_t *)(val & 0xffffffffULL);
        uint8_t *sym_addr = ksyms->name_start + kallsyms_in_memory_read_u32(off, ksyms->len, 0);
        if (sym_addr == addr) {
            kallsyms_in_memory_expand_symbol(ksyms, sym, buf, buflen);
            return sym;
        }
        ptr += sizeof(uint64_t);
    }
    return NULL;
}

static uint8_t *kallsyms_in_memory_init(struct _kallsyms *ksyms, uint8_t *buf, size_t len, size_t offset)
{
    memset(ksyms, 0, sizeof(*ksyms));
    ksyms->buf = buf;
    ksyms->len = len;
    ksyms->symtab_start = kallsyms_in_memory_find_symtab(buf + offset, len - offset);
    if (ksyms->symtab_start == NULL) {
        return NULL;
    }
    ksyms->strtab_start = kallsyms_in_memory_find_strtab(buf + offset, len - offset);
    if (ksyms->strtab_start == NULL) {
        return NULL;
    }
    ksyms->type_table_present = kallsyms_in_memory_is_type_table_present(buf + offset, len - offset);
    if (ksyms->type_table_present) {
        ksyms->type_start = kallsyms_in_memory_find_type_table(buf + offset, len - offset);
        if (ksyms->type_start == NULL) {
            return NULL;
        }
    }
    ksyms->name_start = kallsyms_in_memory_find_name_table(buf + offset, len - offset);
    if (ksyms->name_start == NULL) {
        return NULL;
    }
    ksyms->symtab_end = ksyms->strtab_start;
    ksyms->strtab_end = ksyms->type_table_present ? ksyms->type_start : buf + len;
    ksyms->type_end = ksyms->name_start;
    ksyms->name_end = buf + len;
    return ksyms->symtab_start;
}

static void kallsyms_in_memory_print_symbol(FILE *fp, struct _kallsyms *ksyms, uint8_t *sym, uint8_t *type, uint8_t *addr)
{
    char name[KSYM_NAME_LEN];
    kallsyms_in_memory_expand_symbol(ksyms, sym, name, sizeof(name));
    uint8_t type_val = kallsyms_in_memory_read_u8(type, ksyms->len, 0);
    const char *type_str = (type_val & KSYM_TYPE_MASK) == KSYM_TYPE_FUNC ? "FUNC" : "DATA";
    fprintf(fp, "%016llx %c %s\n", (unsigned long long)addr, type_str[0], name);
}

static void kallsyms_in_memory_print(FILE *fp, struct _kallsyms *ksyms)
{
    uint8_t *ptr = ksyms->symtab_start;
    uint8_t *end = ksyms->symtab_end;
    while (ptr + sizeof(uint64_t) <= end) {
        uint64_t val = kallsyms_in_memory_read_u64(ptr, ksyms->len, 0);
        uint8_t *sym = (uint8_t *)(val & ~0xffffffffULL);
        uint8_t *type = ksyms->type_start + (ptr - ksyms->symtab_start);
        uint8_t *addr = ksyms->name_start + kallsyms_in_memory_read_u32((uint8_t *)(val & 0xffffffffULL), ksyms->len, 0);
        kallsyms_in_memory_print_symbol(fp, ksyms, sym, type, addr);
        ptr += sizeof(uint64_t);
    }
}

static void kallsyms_in_memory_set_verbose_level(int level)
{
    static void kallsyms_in_memory_print_verbose(FILE *fp, struct _kallsyms *ksyms)
    {
        uint8_t *ptr = ksyms->symtab_start;
        uint8_t *end = ksyms->symtab_end;
        int num_symbols = 0;
        while (ptr + sizeof(uint64_t) <= end) {
            num_symbols++;
            ptr += sizeof(uint64_t);
        }
        fprintf(fp, "Found %d symbols in symbol table of size %lu bytes\n", num_symbols, (unsigned long)(ksyms->symtab_end - ksyms->symtab_start));
    }

    static void kallsyms_in_memory_print(FILE *fp, struct _kallsyms *ksyms)
    {
        if (verbose) {
            kallsyms_in_memory_print_verbose(fp, ksyms);
        }
        uint8_t *ptr = ksyms->symtab_start;
        uint8_t *end = ksyms->symtab_end;
        while (ptr + sizeof(uint64_t) <= end) {
            uint64_t val = kallsyms_in_memory_read_u64(ptr, ksyms->len, 0);
            uint8_t *sym = (uint8_t *)(val & ~0xffffffffULL);
            uint8_t *type = ksyms->type_start + (ptr - ksyms->symtab_start);
            uint8_t *addr = ksyms->name_start + kallsyms_in_memory_read_u32((uint8_t *)(val & 0xffffffffULL), ksyms->len, 0);
            kallsyms_in_memory_print_symbol(fp, ksyms, sym, type, addr);
            ptr += sizeof(uint64_t);
        }
    }

    int main(int argc, char **argv)
    {
        verbose = 1;
        struct _kallsyms ksyms;
        uint8_t *buf = (uint8_t *)get_ksymtab();
        size_t len = get_ksymtab_len();
        size_t offset = get_ksymtab_offset();
        if (kallsyms_in_memory_init(&ksyms, buf, len, offset) == NULL) {
            fprintf(stderr, "Failed to initialize kallsyms\n");
            return 1;
        }
        kallsyms_in_memory_print(stdout, &ksyms);
        kallsyms_in_memory_free(&ksyms);
        return 0;
    }
}

static void kallsyms_in_memory_free(struct _kallsyms *ksyms)
{
    memset(ksyms, 0, sizeof(*ksyms));
}