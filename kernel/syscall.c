/*
 * contains the implementation of all syscalls.
 */

#include <errno.h>
#include <stdint.h>

#include "pmm.h"
#include "process.h"
#include "spike_interface/spike_utils.h"
#include "string.h"
#include "syscall.h"
#include "util/functions.h"
#include "util/types.h"
#include "vmm.h"

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char *buf, size_t n)
{
  // buf is now an address in user space of the given app's user stack,
  // so we have to transfer it into phisical address (kernel is running in direct mapping).
  assert(current);
  char *pa = (char *)user_va_to_pa((pagetable_t)(current->pagetable), (void *)buf);
  sprint(pa);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code)
{
  sprint("User exit with code:%d.\n", code);
  // in lab1, PKE considers only one app (one process).
  // therefore, shutdown the system when the app calls exit()
  shutdown(code);
}

uint64 new_page(int size)
{
  // sprint("Trying to allocate new page\n");
  // 如果不存在空闲分区/空闲分区无法满足size要求，分配新页
  void *pa = alloc_page();
  uint64 va = g_ufree_page;
  g_ufree_page += PGSIZE;
  user_vm_map((pagetable_t)current->pagetable, va, size, (uint64)pa,
              prot_to_type(PROT_WRITE | PROT_READ, 1));
  // 创建页描述符
  page_descriptor descriptor;
  descriptor.free_zone_count = 0;
  descriptor.used_zone_count = 0;
  descriptor.va = va;
  descriptor.free_size = PGSIZE;
  // 向分配队列插入
  zone_descriptor used_descriptor;
  used_descriptor.flag = 1;
  used_descriptor.size = size;
  used_descriptor.pa = (uint64)pa;
  used_descriptor.va = va;
  descriptor.used_zones[descriptor.used_zone_count++] = used_descriptor;
  // 向空闲队列插入
  zone_descriptor free_descriptor;
  used_descriptor.flag = 0;
  free_descriptor.size = PGSIZE - size;
  free_descriptor.pa = (uint64)pa + size;
  free_descriptor.va = va + size;
  descriptor.free_zones[descriptor.free_zone_count++] = free_descriptor;
  descriptor.free_size -= size;
  current->pages[current->page_count++] = descriptor;
  // sprint("Allocate size %d To VA:%lx\n", size, va);
  return va;
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page(int size)
{
  // sprint("Trying to allocate size:%d\n", size);
  if (current->page_count == 0)
  {
    return new_page(size);
  }
  else
  {
    for (int i = 0; i < current->page_count; i++)
    {
      // 如果空闲区总大小小于size，则跳过
      if (current->pages[i].free_size < size)
        continue;
      int selected_index = -1;
      uint64 previous_addr = -1;
      page_descriptor descriptor = current->pages[i];
      // sprint("The %d Page with PA at %lx has %d free size,%d free zones,%d used zones\n", i, descriptor.va, descriptor.free_size, descriptor.free_zone_count, descriptor.used_zone_count);
      for (int j = 0; j < descriptor.free_zone_count; j++)
      {
        // sprint("The %d free zone with PA at %lx has %d size\n", j, descriptor.free_zones[j].va, descriptor.free_zones[j].size);
        if (descriptor.free_zones[j].size >= size && (descriptor.free_zones[j].va < previous_addr || previous_addr == -1))
        {
          // sprint("The %d free zone with PA at %lx SUCCESS\n", j, descriptor.free_zones[j].va);
          selected_index = j;
          previous_addr = descriptor.free_zones[j].va;
        }
      }
      if (selected_index != -1)
      {
        descriptor.free_size -= size;
        // sprint("Allocate size %d To VA:%lx left:%d\n", size, descriptor.free_zones[selected_index].va, descriptor.free_size);
        // 向分配队列插入
        zone_descriptor used_descriptor;
        used_descriptor.flag = 1;
        used_descriptor.size = size;
        used_descriptor.pa = descriptor.free_zones[selected_index].pa;
        used_descriptor.va = descriptor.free_zones[selected_index].va;
        descriptor.used_zones[descriptor.used_zone_count++] = used_descriptor;
        descriptor.free_zones[selected_index].size -= size;
        if (descriptor.free_zones[selected_index].size != 0)
        {
          descriptor.free_zones[selected_index].va += size;
          descriptor.free_zones[selected_index].pa += size;
        }
        else
        {
          for (int k = selected_index; k < descriptor.free_zone_count; k++)
          {
            descriptor.free_zones[k] = descriptor.free_zones[k + 1];
          }
          descriptor.used_zone_count--;
        }
        current->pages[i] = descriptor;
        return descriptor.used_zones[descriptor.used_zone_count - 1].va;
      }
    }
    return current->pages[0].free_zones[0].va;
  }
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va)
{
  // sprint("Trying to free va:%lx\n", va);
  for (int i = 0; i < current->page_count; i++)
  {
    page_descriptor descriptor = current->pages[i];
    for (int j = 0; j < descriptor.used_zone_count; j++)
    {
      if (descriptor.used_zones[j].va == va)
      {
        // sprint("The VA at %lx has size %d\n", va, descriptor.used_zones[j].size);
        descriptor.free_size += descriptor.used_zones[j].size;
        // 向空闲队列插入
        zone_descriptor free_descriptor;
        free_descriptor.flag = 0;
        free_descriptor.size = descriptor.used_zones[j].size;
        free_descriptor.pa = descriptor.used_zones[j].pa;
        free_descriptor.va = descriptor.used_zones[j].va;
        descriptor.free_zones[descriptor.free_zone_count++] = free_descriptor;
      }
      current->pages[i] = descriptor;
    }
    if (descriptor.free_size == PGSIZE)
    {
      user_vm_unmap((pagetable_t)current->pagetable, descriptor.va, PGSIZE, 1);
      for (int k = i; k < current->page_count; k++)
      {
        current->pages[k] = current->pages[k + 1];
      }
      current->page_count--;
    }
    return 0;
  }
  return 0;
}

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
  switch (a0)
  {
  case SYS_user_print:
    return sys_user_print((const char *)a1, a2);
  case SYS_user_exit:
    return sys_user_exit(a1);
  // added @lab2_2
  case SYS_user_allocate_page:
    return sys_user_allocate_page(a1);
  case SYS_user_free_page:
    return sys_user_free_page(a1);
  default:
    panic("Unknown syscall %ld \n", a0);
  }
}
