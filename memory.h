#ifndef __KALLSYMSPRINT_H__
#define __KALLSYMSPRINT_H__

#include <stdbool.h>
#include <stdio.h>

struct kallsyms;

struct kallsyms* kallsyms_in_memory_init(void* mem, size_t len);
void kallsyms_in_memory_free(struct kallsyms* ks);
unsigned long kallsyms_in_memory_lookup_name(struct kallsyms* ks, const char* name);
int kallsyms_in_memory_lookup_names(struct kallsyms* ks, const char* name, unsigned long* addr, int limit);
const char* kallsyms_in_memory_lookup_address(struct kallsyms* ks, unsigned long addr);
bool is_address_in_kallsyms_table(struct kallsyms* ks, unsigned long addr);
void kallsyms_in_memory_set_verbose(bool verbose);
void kallsyms_in_memory_print_all(struct kallsyms* ks);
void kallsyms_in_memory_print_all_to_file(struct kallsyms* ks, FILE* fp);

#endif