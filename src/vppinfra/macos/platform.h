/*
 * Copyright (c) 2023 VPP Contributors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_vppinfra_macos_platform_h
#define included_vppinfra_macos_platform_h

#ifdef __APPLE__

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/machine.h>
#include <pthread.h>

/* Auxiliary vector compatibility for macOS */
#define AT_NULL    0
#define AT_HWCAP   16
#define AT_HWCAP2  26
#define AT_PLATFORM 15

/* On macOS, getauxval is not available, so we provide a stub implementation */
static inline unsigned long
getauxval(unsigned long type)
{
  /* macOS doesn't have auxv, so return 0 for all types */
  return 0;
}

/* macOS equivalent of Linux's get_nprocs() */
static inline int
get_nprocs(void)
{
  int count;
  size_t size = sizeof(count);
  if (sysctlbyname("hw.logicalcpu", &count, &size, NULL, 0) < 0)
    return 1;  /* Default to 1 on error */
  return count;
}

/* macOS equivalent of Linux's get_nprocs_conf() */
static inline int
get_nprocs_conf(void)
{
  int count;
  size_t size = sizeof(count);
  if (sysctlbyname("hw.physicalcpu", &count, &size, NULL, 0) < 0)
    return 1;  /* Default to 1 on error */
  return count;
}

/* macOS implementations of Linux mmap flags */
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0
#endif

#ifndef MAP_LOCKED
#define MAP_LOCKED 0
#endif

#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

/* Additional network-related definitions */
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#endif /* __APPLE__ */
#endif /* included_vppinfra_macos_platform_h */
