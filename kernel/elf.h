#ifndef _ELF_H_
#define _ELF_H_

#include "process.h"
#include "util/types.h"

#define MAX_CMDLINE_ARGS 64

// elf header structure
typedef struct elf_header_t
{
  uint32 magic;
  uint8 elf[12];
  uint16 type;      /* Object file type */
  uint16 machine;   /* Architecture */
  uint32 version;   /* Object file version */
  uint64 entry;     /* Entry point virtual address */
  uint64 phoff;     /* Program header table file offset */
  uint64 shoff;     /* Section header table file offset */
  uint32 flags;     /* Processor-specific flags */
  uint16 ehsize;    /* ELF header size in bytes */
  uint16 phentsize; /* Program header table entry size */
  uint16 phnum;     /* Program header table entry count */
  uint16 shentsize; /* Section header table entry size */
  uint16 shnum;     /* Section header table entry count */
  uint16 shstrndx;  /* Section header string table index */
} elf_header;

// Program segment header.
typedef struct elf_prog_header_t
{
  uint32 type;   /* Segment type */
  uint32 flags;  /* Segment flags */
  uint64 off;    /* Segment file offset */
  uint64 vaddr;  /* Segment virtual address */
  uint64 paddr;  /* Segment physical address */
  uint64 filesz; /* Segment size in file */
  uint64 memsz;  /* Segment size in memory */
  uint64 align;  /* Segment alignment */
} elf_prog_header;

// section header
typedef struct elf_section_header_t
{
  uint32 sh_name;      // 节区名
  uint32 sh_type;      // 节区类型，取值依次为STT_NOTYPE、SHT_PROGBITS、SHT_SYMTAB、SHT_STRTAB，其中SHT_SYMTAB表示符号表的section header，SHT_STRTAB表示字符串表的section header
  uint64 sh_flags;     // 节区标志
  uint64 sh_addr;      // 节区第一个字节的地址
  uint64 sh_offset;    // 节区第一个字节与文件头之间的偏移
  uint64 sh_size;      // 节区字节数
  uint32 sh_link;      // 节区头部表索引链接
  uint32 sh_info;      // 节区信息
  uint64 sh_addralign; // 节区地址对齐约束
  uint64 sh_entsize;   // 每个表项的字节数
} elf_section_header;

// symtab item
typedef struct elf_symtab_item_t
{
  uint32 st_name; // 符号名称，这里的符号名称是索引值
  uint8 st_info; // 符号的属性和类型，包括两部分：高4位表示Symbol Binding，低4位表示符号类型
  // 符号类型的取值依次为STT_NOTYPE、STT_OBJECT、STT_FUNC、STT_SECTION、STT_FILE、STT_COMMON、STT_TLS等，其中STT_FUNC即表示关联到一个函数或者其他可执行的代码
  uint8 st_other; // 未定义
  uint16 st_shndx; // 相关的节区头部表索引
  uint64 st_value; // 符号取值
  uint64 st_size;  // 符号大小
} elf_symtab_item;

#define ELF_MAGIC 0x464C457FU // "\x7FELF" in little endian
#define ELF_PROG_LOAD 1

// 符号类型
#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_COMMON 5
#define STT_TLS 6
// section header类型
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3

typedef enum elf_status_t
{
  EL_OK = 0,

  EL_EIO,
  EL_ENOMEM,
  EL_NOTELF,
  EL_ERR,

} elf_status;

typedef struct elf_ctx_t
{
  void *info;
  elf_header ehdr;
} elf_ctx;

elf_status elf_init(elf_ctx *ctx, void *info);
elf_status elf_load(elf_ctx *ctx);

void load_bincode_from_host_elf(process *p);
uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset);
void elf_print_backtrace(uint64 entry_point, int level);

#endif
