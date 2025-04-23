/*
 * Copyright (c) 2023 VPP Contributors
 *
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

#ifdef __APPLE__
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

/* macOS specific initialization */
static clib_error_t *
unix_mac_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (unix_mac_init);
#endif /* __APPLE__ */

