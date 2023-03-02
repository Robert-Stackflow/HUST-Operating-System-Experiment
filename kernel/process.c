/*
 * Utility functions for process management.
 *
 * Note: in Lab1, only one process (i.e., our user application) exists. Therefore,
 * PKE OS at this stage will set "current" to the loaded user application, and also
 * switch to the old "current" process after trap handling.
 */

#include "process.h"
#include "config.h"
#include "elf.h"
#include "riscv.h"
#include "spike_interface/spike_utils.h"
#include "strap.h"
#include "string.h"

// Two functions defined in kernel/usertrap.S
extern char smode_trap_vector[];
extern void return_to_user(trapframe *);

// current points to the currently running user-mode application.
process *current = NULL;

//
// switch to a user-mode process
//
void switch_to(process *proc)
{
  assert(proc);
  current = proc;

  // write the smode_trap_vector (64-bit func. address) defined in kernel/strap_vector.S
  // to the stvec privilege register, such that trap handler pointed by smode_trap_vector
  // will be triggered when an interrupt occurs in S mode.
  write_csr(stvec, (uint64)smode_trap_vector);

  // set up trapframe values (in process structure) that smode_trap_vector will need when
  // the process next re-enters the kernel.
  proc->trapframe->kernel_sp = proc->kstack; // process's kernel stack
  proc->trapframe->kernel_trap = (uint64)smode_trap_handler;

  // SSTATUS_SPP and SSTATUS_SPIE are defined in kernel/riscv.h
  // set S Previous Privilege mode (the SSTATUS_SPP bit in sstatus register) to User mode.
  unsigned long x = read_csr(sstatus);
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode

  // write x back to 'sstatus' register to enable interrupts, and sret destination mode.
  write_csr(sstatus, x);

  // set S Exception Program Counter (sepc register) to the elf entry pc.
  write_csr(sepc, proc->trapframe->epc);

  // return_to_user() is defined in kernel/strap_vector.S. switch to user mode with sret.
  return_to_user(proc->trapframe);
}

char *my_strcpy(char *dest, const char *src)
{
  char *d = dest;
  while ((*d++ = *src++))
    ;
  return --d;
}

void print_errorline()
{
  uint64 addr = read_csr(mepc);
  sprint("%p\n",addr);
  for (int k = 0; k < current->line_ind; k++)
  {
    if (addr == current->line[k].addr && current->line[k].line > 0)
    {
      char path[100];
      char file[5000];
      int line_index = current->line[k].line;
      my_strcpy(my_strcpy(my_strcpy(path, current->dir[current->file[current->line[k].file].dir]), "/"), current->file[current->line[k].file].file);
      sprint("Runtime error at %s:%d\n", path, line_index);
      spike_file_t *fp = spike_file_open(path, O_RDONLY, 0);
      if (IS_ERR_VALUE(fp))
        panic("Fail on openning file %s .\n", path);
      int length = spike_file_pread(fp, file, 5000, 0);
      int line_count = 1;
      for (int i = 0; i < length; i++)
      {
        if (file[i] == '\n')
        {
          if ((++line_count) == line_index)
          {
            for (int j = i + 1; j < length; j++)
            {
              sprint("%c", file[j]);
              if (file[j] == '\n')
                break;
            }
            break;
          }
        }
      }
      spike_file_close(fp);
    }
  }
}