/*
 * This is small demo lib used to parse ELF executable file.
 * The purpose to create this lib is I want to show you:
 * 1. Some basic knowledge about ELF file format
 * 2. It will be used in my educational linux binary debugger called my_gdb
 *
 * There're many limitations for this library to work.
 * See the companion REAME.
 *
 * Author: Changyi Yan & ChatGPT
 * Contact: yanchangyi87@gmail.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdbool.h>
#include "libelf_parser.h"

void elf_parser_ignore_protection(struct elf_parser *parser, bool ignore)
{
    if (ignore)
    {
        parser->ignore_protection = true;
    }
    else
    {
        parser->ignore_protection = false;
    }
}

static Elf64_Shdr *elf_parser_get_section_header(struct elf_parser *parser, uint64_t target_section)
{
    for (int i = 0; i < parser->elf_header->e_shnum; i++)
    {
        Elf64_Shdr sh = parser->elf_section_header[i];
        if (sh.sh_type == target_section)
        {
            return &parser->elf_section_header[i];
        }
    }

    return NULL;
}

static Elf64_Dyn *elf_parser_get_dyn_item(struct elf_parser *parser, Elf64_Sxword dtag)
{
    int dyn_num = 0;
    Elf64_Dyn *dyn_base = NULL;

    Elf64_Shdr *sh = elf_parser_get_section_header(parser, SHT_DYNAMIC);
    if (!sh)
    {
        printf("No Dynamic Section.\n");
        return NULL;
    }

    dyn_num = sh->sh_size / sh->sh_entsize;
    dyn_base = (Elf64_Dyn *)(parser->mem + sh->sh_offset);
    for (int i = 0; i < dyn_num; i++)
    {
        Elf64_Dyn dyn = dyn_base[i];
        if (dyn.d_tag == dtag)
        {
            return &dyn_base[i];
        }
    }

    return NULL;
}

struct elf_parser *new_elf_parser(const char *filename)
{
    int res = 0;
    struct elf_parser *parser = NULL;
    int fd;
    int filename_len = 0;
    struct stat statbuf;

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        perror("Open file failed\n");
        goto err;
    }

    parser = calloc(1, sizeof(struct elf_parser));
    if (!parser)
    {
        perror("Can't allocate memory.");
        goto err;
    }

    res = fstat(fd, &statbuf);
    if (res == -1)
    {
        perror("Stat file failed.");
        goto err;
    }

    filename_len = strlen(filename);
    strncpy(parser->filename, filename, filename_len >= FILENAME_MAX_SIZE ? FILENAME_MAX_SIZE - 1 : filename_len);
    parser->map_size = statbuf.st_size;

    parser->mem = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (parser->mem == MAP_FAILED)
    {
        perror("Map file into vm failed.");
        goto err;
    }
    goto ok;

err:
    destroy_parser(parser);
ok:
    close(fd);
    return parser;
}

void destroy_parser(struct elf_parser *parser)
{
    if (parser)
    {
        if (parser->mem != MAP_FAILED && parser->mem != NULL)
        {
            munmap(parser->mem, parser->map_size);
        }
        free(parser);
    }
}

int elf_parser_parse_elf_image(struct elf_parser *parser)
{
    Elf64_Shdr *sh;
    parser->elf_header = (Elf64_Ehdr *)(parser->mem);
    parser->elf_section_header = (Elf64_Shdr *)(parser->mem + parser->elf_header->e_shoff);
    parser->elf_program_header = (Elf64_Phdr *)(parser->mem + parser->elf_header->e_phoff);

    if (parser->elf_header->e_ident[0] != 0x7F || strncmp(&parser->elf_header->e_ident[1], "ELF", 3) != 0)
    {
        return -ERR_NOT_ELF;
    }

    if (parser->elf_header->e_type != ET_EXEC && parser->elf_header->e_type != ET_DYN)
    {
        return -ERR_NOT_EXEC;
    }

    // we need first to check it's a position independent executable.
    if (!parser->ignore_protection && elf_parser_check_if_pie(parser) != SWITCH_OFF)
    {
        printf("PIE is enable or state unkonwn.\n");
        return -ERR_PIE_ENABLED;
    }
    sh = elf_parser_get_section_header(parser, SHT_SYMTAB);
    if (sh)
    {
        parser->elf_symbol_table = (Elf64_Sym *)(parser->mem + sh->sh_offset);
        parser->elf_symbol_number = sh->sh_size / sh->sh_entsize;
        parser->elf_string_table = parser->mem + parser->elf_section_header[sh->sh_link].sh_offset;
    }

    return ERR_ELF_OK;
}

uint8_t elf_parser_check_if_pie(struct elf_parser *parser)
{
    // how to check if a program is pie?
    // check dynamic linking information
    // 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
    // NOW: DF_1_NOW        0x00000001      Set RTLD_NOW for this object.
    // PIE: DF_1_PIE        0x08000000
    // if this exists, then pie
    // apart from this, we also need to check alsr global switch
    // read /proc/sys/kernel/randomize_va_space
    char alsr_switch[8] = {0};
    int ret;
    Elf64_Shdr *sh;
    Elf64_Dyn *dyn;
    int dyn_num = 0;

    int fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
    if (fd == -1)
    {
        perror("Can't open aslr switch file.");
        parser->is_alsr_enabled = false;
    }
    else
    {
        ret = read(fd, alsr_switch, sizeof(alsr_switch));
        if (ret == -1)
        {
            perror("Can't read aslr switch value.");
            parser->is_alsr_enabled = SWITCH_UNKNOWN;
        }
        else
        {
            alsr_switch[strlen(alsr_switch) - 1] = '\0';
            if (atoi(alsr_switch) > 0)
            {
                parser->is_alsr_enabled = SWITCH_ON;
            }
            else
            {
                parser->is_alsr_enabled = SWITCH_OFF;
            }
        }
    }

    dyn = elf_parser_get_dyn_item(parser, DT_FLAGS_1);
    if (!dyn)
    {
        parser->elf_is_pie = SWITCH_OFF;
    }
    else
    {
        if (dyn->d_un.d_val & DF_1_PIE)
        {
            parser->elf_is_pie = SWITCH_ON;
        }
        else
        {
            parser->elf_is_pie = SWITCH_OFF;
        }
    }

    if (parser->is_alsr_enabled == SWITCH_UNKNOWN || parser->elf_is_pie == SWITCH_UNKNOWN)
        return SWITCH_UNKNOWN;

    if (parser->elf_is_pie == SWITCH_ON && parser->is_alsr_enabled == SWITCH_ON)
        return SWITCH_ON;

    return SWITCH_OFF;
}

Elf64_Addr elf_parser_lookup_symbol(struct elf_parser *parser, const char *sym_str)
{
    if (parser->elf_symbol_table)
    {
        for (int i = 0; i < parser->elf_symbol_number; i++)
        {
            Elf64_Sym sym = parser->elf_symbol_table[i];
            if (strncmp(&parser->elf_string_table[sym.st_name], sym_str, sizeof(sym_str)) == 0)
            {
                return sym.st_value;
            }
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // Todo: check arguments

    int res = 0;

    struct elf_parser *parser = new_elf_parser((const char *)argv[1]);
    if (!parser)
    {
        exit(-1);
    }

    if (argc >= 4 && strncmp(argv[3], "ignore", strlen("ignore")) == 0)
    {
        elf_parser_ignore_protection(parser, true);
    }

    res = elf_parser_parse_elf_image(parser);
    if (res != ERR_ELF_OK)
        return res;

    Elf64_Addr sym_addr = elf_parser_lookup_symbol(parser, argv[2]);
    printf("%s is at 0x%lx\n", argv[2], sym_addr);

    destroy_parser(parser);
    return 0;
}