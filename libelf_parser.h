#ifndef __LIBELF_PARSER_C__
#define __LIBELF_PARSER_C__

#include <stddef.h>
#include <elf.h>
#include <stdbool.h>

#define FILENAME_MAX_SIZE 256

// this is served as return code for caller
// ERR_GENERAL_ERR means error not due to elf file
enum err_code
{
    ERR_ELF_OK,
    ERR_GENERAL_ERR,
    ERR_NOT_ELF,
    ERR_NOT_EXEC,
    ERR_PIE_ENABLED
};

enum SWITCH_STATE
{
    SWITCH_ON,
    SWITCH_OFF,
    SWITCH_UNKNOWN
};

struct elf_parser
{
    char filename[FILENAME_MAX_SIZE];
    uint8_t *mem;
    size_t map_size;

    Elf64_Ehdr *elf_header;
    Elf64_Shdr *elf_section_header;
    Elf64_Phdr *elf_program_header;
    Elf64_Sym *elf_symbol_table;
    size_t elf_symbol_number;
    char *elf_string_table;
    uint8_t elf_is_pie;
    uint8_t is_alsr_enabled;
    bool ignore_protection;
};

struct elf_parser *new_elf_parser(const char *filename);
void destroy_parser(struct elf_parser *parser);
int elf_parser_parse_elf_image(struct elf_parser *parser);
Elf64_Addr elf_parser_lookup_symbol(struct elf_parser *parser, const char *sym);
uint8_t elf_parser_check_if_pie(struct elf_parser *parser);
void elf_parser_ignore_protection(struct elf_parser *parser, bool ignore);

#endif