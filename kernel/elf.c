/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "riscv.h"
#include "spike_interface/spike_utils.h"
#include "string.h"
// 字符串表
char strtab[200];
// symtab表项数
int symtab_items_count = 0;
// symtab表项
elf_symtab_item symtab_items[100];

typedef struct elf_info_t
{
  spike_file_t *f;
  process *p;
} elf_info;

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
uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset)
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

//
// load the elf segments to memory regions as we are in Bare mode in lab1
//
elf_status elf_load(elf_ctx *ctx)
{
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  // strtab的section header
  elf_section_header strtab_section_header;
  // symtab的section header
  elf_section_header symtab_section_header;
  // symtab
  elf_symtab_item symtab_item;
  int i, offset;

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

    // 获取.strtab的section header，此时off初始为section区偏移，结束条件为section区数目
    for (i = 0, offset = ctx->ehdr.shoff; i < ctx->ehdr.shnum; i++, offset += sizeof(strtab_section_header))
    {
      if (elf_fpread(ctx, &strtab_section_header, sizeof(strtab_section_header), offset) != sizeof(strtab_section_header))
        return EL_EIO;
      if (strtab_section_header.sh_type == SHT_STRTAB)
        break;
    }
    // 获取.symtab的section header，此时off初始为section区偏移，结束条件为section区数目
    for (i = 0, offset = ctx->ehdr.shoff; i < ctx->ehdr.shnum; i++, offset += sizeof(symtab_section_header))
    {
      if (elf_fpread(ctx, (void *)&symtab_section_header, sizeof(symtab_section_header), offset) != sizeof(symtab_section_header))
        return EL_EIO;
      if (symtab_section_header.sh_type == SHT_SYMTAB)
        break;
    }
    // 获取字符串表
    if (elf_fpread(ctx, (void *)strtab, sizeof(strtab), strtab_section_header.sh_offset) != sizeof(strtab))
      return EL_EIO;
    // 获取类型为STT_FUNC的symtab表项，此时off初始为symtab的section header中记录的偏移，结束条件为symtab表项数，通过size/entsize计算
    for (i = 0, offset = symtab_section_header.sh_offset; i < symtab_section_header.sh_size / symtab_section_header.sh_entsize; i++, offset += sizeof(symtab_item))
    {
      if (elf_fpread(ctx, (void *)&symtab_item, sizeof(symtab_item), offset) != sizeof(symtab_item))
        return EL_EIO;
      // 取st_info的低4位，即符号类型字段
      if ((symtab_item.st_info & 0xf) == STT_FUNC)
        symtab_items[symtab_items_count++] = symtab_item;
    }
  }

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
}

void elf_print_backtrace(uint64 addr, int level)
{
  for (; level > 0; level--)
  {
    for (int i = 0; i < symtab_items_count; i++)
    {
      if (symtab_items[i].st_value == addr)
      {
        // 如果找到某个symtab表项的值等于addr，则打印输出其名称，即strtab首地址+偏移
        sprint("%s\n", strtab + symtab_items[i].st_name);
        // 如果该函数名为main，则结束打印
        if (strcmp(strtab + symtab_items[i].st_name, "main") == 0)
          return;
        addr += symtab_items[i].st_size;
        break;
      }
    }
  }
}
