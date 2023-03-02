/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "riscv.h"
#include "spike_interface/spike_utils.h"
#include "string.h"

typedef struct elf_info_t
{
    spike_file_t *f;
    process *p;
} elf_info;
// 字符串表
char strtab[200];
uint64 debug_line_size;
char debug_line[1000];
//
// the implementation of allocater. allocates memory space for later segment loading
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size)
{
    // directly returns the virtual address as we are in the Bare mode in lab1_x
    return (void *)elf_va;
}

//
// actual file reading, using the spike file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset)
{
    elf_info *msg = (elf_info *)ctx->info;
    // call spike file utility to load the content of elf file into memory.
    // spike_file_pread will read the elf file (msg->f) from offset to memory (indicated by
    // *dest) for nb bytes.
    return spike_file_pread(msg->f, dest, nb, offset);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info)
{
    ctx->info = info;

    // load the elf header
    if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr))
        return EL_EIO;

    // check the signature (magic value) of the elf
    if (ctx->ehdr.magic != ELF_MAGIC)
        return EL_NOTELF;

    return EL_OK;
}

// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **offset)
{
    uint64 value = 0;
    int shift = 0;
    uint8 b;
    for (;;)
    {
        b = *(uint8 *)(*offset);
        (*offset)++;
        value |= ((uint64)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0)
            break;
    }
    if (out)
        *out = value;
}
void read_sleb128(int64 *out, char **offset)
{
    int64 value = 0;
    int shift = 0;
    uint8 b;
    for (;;)
    {
        b = *(uint8 *)(*offset);
        (*offset)++;
        value |= ((uint64_t)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0)
            break;
    }
    if (shift < 64 && (b & 0x40))
        value |= -(1 << shift);
    if (out)
        *out = value;
}
// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **offset)
{
    *out = 0;
    for (int i = 0; i < 8; i++)
    {
        *out |= (uint64)(**offset) << (i << 3);
        (*offset)++;
    }
}
void read_uint32(uint32 *out, char **offset)
{
    *out = 0;
    for (int i = 0; i < 4; i++)
    {
        *out |= (uint32)(**offset) << (i << 3);
        (*offset)++;
    }
}
void read_uint16(uint16 *out, char **offset)
{
    *out = 0;
    for (int i = 0; i < 2; i++)
    {
        *out |= (uint16)(**offset) << (i << 3);
        (*offset)++;
    }
}

/*
 * analyzis the data in the debug_line section
 *
 * the function needs 3 parameters: elf context, data in the debug_line section
 * and length of debug_line section
 *
 * make 3 arrays:
 * "process->dir" stores all directory paths of code files
 * "process->file" stores all code file names of code files and their directory path index of array "dir"
 * "process->line" stores all relationships map instruction addresses to code line numbers
 * and their code file name index of array "file"
 */
void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length)
{
    process *p = ((elf_info *)ctx->info)->p;
    p->debugline = debug_line;
    // directory name char pointer array
    p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3);
    int dir_ind = 0, dir_base;
    // file name char pointer array
    p->file = (code_file *)(p->dir + 64);
    int file_ind = 0, file_base;
    // table array
    p->line = (addr_line *)(p->file + 64);
    p->line_ind = 0;
    char *offset = debug_line;
    while (offset < debug_line + length)
    { // iterate each compilation unit(CU)
        debug_header *dh = (debug_header *)offset;
        offset += sizeof(debug_header);
        dir_base = dir_ind;
        file_base = file_ind;
        // get directory name char pointer in this CU
        while (*offset != 0)
        {
            p->dir[dir_ind++] = offset;
            while (*offset != 0)
                offset++;
            offset++;
        }
        offset++;
        // get file name char pointer in this CU
        while (*offset != 0)
        {
            p->file[file_ind].file = offset;
            while (*offset != 0)
                offset++;
            offset++;
            uint64 dir;
            read_uleb128(&dir, &offset);
            p->file[file_ind++].dir = dir - 1 + dir_base;
            read_uleb128(NULL, &offset);
            read_uleb128(NULL, &offset);
        }
        offset++;
        addr_line regs;
        regs.addr = 0;
        regs.file = 1;
        regs.line = 1;
        // simulate the state machine op code
        for (;;)
        {
            uint8 op = *(offset++);
            switch (op)
            {
            case 0: // Extended Opcodes
                read_uleb128(NULL, &offset);
                op = *(offset++);
                switch (op)
                {
                case 1: // DW_LNE_end_sequence
                    if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr)
                        p->line_ind--;
                    p->line[p->line_ind] = regs;
                    p->line[p->line_ind].file += file_base - 1;
                    p->line_ind++;
                    goto endop;
                case 2: // DW_LNE_set_address
                    read_uint64(&regs.addr, &offset);
                    break;
                // ignore DW_LNE_define_file
                case 4: // DW_LNE_set_discriminator
                    read_uleb128(NULL, &offset);
                    break;
                }
                break;
            case 1: // DW_LNS_copy
                if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr)
                    p->line_ind--;
                p->line[p->line_ind] = regs;
                p->line[p->line_ind].file += file_base - 1;
                p->line_ind++;
                break;
            case 2:
            { // DW_LNS_advance_pc
                uint64 delta;
                read_uleb128(&delta, &offset);
                regs.addr += delta * dh->min_instruction_length;
                break;
            }
            case 3:
            { // DW_LNS_advance_line
                int64 delta;
                read_sleb128(&delta, &offset);
                regs.line += delta;
                break;
            }
            case 4: // DW_LNS_set_file
                read_uleb128(&regs.file, &offset);
                break;
            case 5: // DW_LNS_set_column
                read_uleb128(NULL, &offset);
                break;
            case 6: // DW_LNS_negate_stmt
            case 7: // DW_LNS_set_basic_block
                break;
            case 8:
            { // DW_LNS_const_add_pc
                int adjust = 255 - dh->opcode_base;
                int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                regs.addr += delta;
                break;
            }
            case 9:
            { // DW_LNS_fixed_advanced_pc
                uint16 delta;
                read_uint16(&delta, &offset);
                regs.addr += delta;
                break;
            }
                // ignore 10, 11 and 12
            default:
            { // Special Opcodes
                int adjust = op - dh->opcode_base;
                int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                int line_delta = dh->line_base + (adjust % dh->line_range);
                regs.addr += addr_delta;
                regs.line += line_delta;
                if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr)
                    p->line_ind--;
                p->line[p->line_ind] = regs;
                p->line[p->line_ind].file += file_base - 1;
                p->line_ind++;
                break;
            }
            }
        }
    endop:;
    }
}

//
// load the elf segments to memory regions as we are in Bare mode in lab1
//
elf_status elf_load(elf_ctx *ctx)
{
    // elf_prog_header structure is defined in kernel/elf.h
    elf_prog_header ph_addr;
    int i, offset;
    // strtab的section header
    elf_sect_header strtab_section_header;
    // debug_line的section header
    elf_sect_header debug_line_section_header;

    // traverse the elf program segment headers
    for (i = 0, offset = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, offset += sizeof(ph_addr))
    {
        // read segment headers
        if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), offset) != sizeof(ph_addr))
            return EL_EIO;

        if (ph_addr.type != ELF_PROG_LOAD)
            continue;
        if (ph_addr.memsz < ph_addr.filesz)
            return EL_ERR;
        if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr)
            return EL_ERR;

        // allocate memory block before elf loading
        void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

        // actual loading
        if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
            return EL_EIO;
    }
    // 获取.strtab的section header，此时off初始为section区偏移，结束条件为section区数目
    for (i = 0, offset = ctx->ehdr.shoff; i < ctx->ehdr.shnum; i++, offset += sizeof(strtab_section_header))
    {
        if (elf_fpread(ctx, &strtab_section_header, sizeof(strtab_section_header), offset) != sizeof(strtab_section_header))
            return EL_EIO;
        if (i==ctx->ehdr.shstrndx)
            break;
    }
    // 获取字符串表
    if (elf_fpread(ctx, (void *)strtab, sizeof(strtab), strtab_section_header.offset) != sizeof(strtab))
        return EL_EIO;
    // 获取.debug_line的section header，此时off初始为section区偏移，结束条件为section区数目
    for (i = 0, offset = ctx->ehdr.shoff; i < ctx->ehdr.shnum; i++, offset += sizeof(debug_line_section_header))
    {
        if (elf_fpread(ctx, &debug_line_section_header, sizeof(debug_line_section_header), offset) != sizeof(debug_line_section_header))
            return EL_EIO;
        // sprint("Type:%d Offset:%3d Name:%s\n", debug_line_section_header.type, debug_line_section_header.name, strtab + debug_line_section_header.name);
        if (debug_line_section_header.type == SHT_PROGBITS && strcmp(strtab + debug_line_section_header.name, ".debug_line") == 0)
            break;
    }
    // 读取debug_line内容
    debug_line_size = debug_line_section_header.size;
    // sprint("%d\n",debug_line_section_header.size);
    if (elf_fpread(ctx, (void *)debug_line, sizeof(debug_line), debug_line_section_header.offset) != sizeof(debug_line))
        return EL_EIO;
    return EL_OK;
}

typedef union
{
    uint64 buf[MAX_CMDLINE_ARGS];
    char *argv[MAX_CMDLINE_ARGS];
} arg_buf;

//
// returns the number (should be 1) of string(s) after PKE kernel in command line.
// and store the string(s) in arg_bug_msg.
//
static size_t parse_args(arg_buf *arg_bug_msg)
{
    // HTIFSYS_getmainvars frontend call reads command arguments to (input) *arg_bug_msg
    long r = frontend_syscall(HTIFSYS_getmainvars, (uint64)arg_bug_msg,
                              sizeof(*arg_bug_msg), 0, 0, 0, 0, 0);
    kassert(r == 0);

    size_t pk_argc = arg_bug_msg->buf[0];
    uint64 *pk_argv = &arg_bug_msg->buf[1];

    int arg = 1; // skip the PKE OS kernel string, leave behind only the application name
    for (size_t i = 0; arg + i < pk_argc; i++)
        arg_bug_msg->argv[i] = (char *)(uintptr_t)pk_argv[arg + i];

    // returns the number of strings after PKE kernel in command line
    return pk_argc - arg;
}

//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p)
{
    arg_buf arg_bug_msg;

    // retrieve command line arguements
    size_t argc = parse_args(&arg_bug_msg);
    if (!argc)
        panic("You need to specify the application program!\n");

    sprint("Application: %s\n", arg_bug_msg.argv[0]);

    // elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
    elf_ctx elfloader;
    // elf_info is defined above, used to tie the elf file and its corresponding process.
    elf_info info;

    info.f = spike_file_open(arg_bug_msg.argv[0], O_RDONLY, 0);
    info.p = p;
    // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
    if (IS_ERR_VALUE(info.f))
        panic("Fail on openning the input application program.\n");

    // init elfloader context. elf_init() is defined above.
    if (elf_init(&elfloader, &info) != EL_OK)
        panic("fail to init elfloader.\n");

    // load elf. elf_load() is defined above.
    if (elf_load(&elfloader) != EL_OK)
        panic("Fail on loading elf.\n");

    // entry (virtual, also physical in lab1_x) address
    p->trapframe->epc = elfloader.ehdr.entry;

    // close the host spike file
    spike_file_close(info.f);

    sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
    make_addr_line(&elfloader, debug_line, debug_line_size);
    for (int i = 0; i < info.p->line_ind; i++)
        sprint("%p %d %d\n", info.p->line[i].addr, info.p->line[i].line, info.p->line[i].file);
}
