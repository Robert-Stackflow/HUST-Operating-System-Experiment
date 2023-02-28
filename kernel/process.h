#ifndef _PROC_H_
#define _PROC_H_

#include "riscv.h"

typedef struct trapframe_t
{
  // space to store context (all common registers)
  /* offset:0   */ riscv_regs regs;

  // process's "user kernel" stack
  /* offset:248 */ uint64 kernel_sp;
  // pointer to smode_trap_handler
  /* offset:256 */ uint64 kernel_trap;
  // saved user process counter
  /* offset:264 */ uint64 epc;

  // kernel page table. added @lab2_1
  /* offset:272 */ uint64 kernel_satp;
} trapframe;
// 分区描述符
typedef struct zone_descriptor_t
{
  int flag; // 是否占用
  int size;
  uint64 pa;
  uint64 va;
} zone_descriptor;
// 页描述符
typedef struct page_descriptor_t
{
  uint64 va;               // 页首地址
  int free_size;                 // 空闲区总大小
  int used_zone_count;           // 已使用分区数
  int free_zone_count;           // 未使用分区数
  zone_descriptor used_zones[5]; // 已使用分区列表
  zone_descriptor free_zones[5]; // 未使用分区列表
} page_descriptor;
// the extremely simple definition of process, used for begining labs of PKE
typedef struct process_t
{
  // pointing to the stack used in trap handling.
  uint64 kstack;
  // user page table
  pagetable_t pagetable;
  // trapframe storing the context of a (User mode) process.
  trapframe *trapframe;
  int page_count;           // 页数
  page_descriptor pages[5];
} process;
// switch to run user app
void switch_to(process *);

// current running process
extern process *current;

// address of the first free page in our simple heap. added @lab2_2
extern uint64 g_ufree_page;

#endif
