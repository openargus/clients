/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/* Routines to fetch values from the Windows registry
 *
 * These functions only operate on the 64-bit registry view,
 * regardless of CPU architecture or word size.
 *
 *
 * Eric Kinzie <eric@qosient.com>
 * Nov 2018
 */
#include "argus_config.h"

#if defined(__CYGWIN__) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
# include <windows.h>
# include <sys/types.h>
# include "argus_windows_registry.h"

/* These functions return zero on success, a Windows System Error Code
 * (greater than zero) if one of the Windows API functions failed, or a
 * negative value for any non-Windows error.
 */

int
ArgusWindowsRegistryOpenKey(HKEY hkey, const char * const keyname,
                            HKEY *handle)
{
   return RegOpenKeyEx(hkey, TEXT(keyname), 0, KEY_READ|KEY_WOW64_64KEY,
                       handle);
}

int
ArgusWindowsRegistryCloseKey(HKEY handle)
{
   return RegCloseKey(handle);
}

int
ArgusWindowsRegistryGetQWORD(HKEY handle, const char * const valname,
                             long long *val)
{
   LONGLONG qwValue;
   DWORD dwType;
   DWORD dwSize = sizeof(qwValue);
   int res = 0;

   res = RegQueryValueEx(handle, TEXT(valname), 0, &dwType, (LPBYTE)&qwValue,
                         &dwSize);
   if (res == ERROR_SUCCESS) {
      if (dwType == REG_QWORD)
         *val = (long long)qwValue;
      else
         res = -1;
   }

   return res;
}

/* ArgusWindowsGetRegistrySZ: char *val may get clobbered, even when
 * failure indication returned.
 */
int
ArgusWindowsRegistryGetSZ(HKEY handle, const char * const valname, char *val,
                          size_t vlen /* bytes allocated for val */)
{
   DWORD dwType;
   DWORD dwSize = (DWORD)vlen;
   int res = 0;

   res = RegQueryValueEx(handle, TEXT(valname), 0, &dwType, (LPBYTE)val,
                         &dwSize);
   if (res == ERROR_SUCCESS) {
      if (dwType == REG_SZ)
         *(val+vlen-1) = 0;  /* NULL terminate, just in case */
      else
         res = -1;
   }

   return res;
}
#endif /* CYGWIN, _MSC_VER, . . . */

#if 0

/*
 * The following example uses these values in the registry:
 *
 * PS C:\Users\ekinzie> Get-ItemProperty HKLM:\SOFTWARE\QoSient\ArgusClients\ramanage
 *
 *
 * RAMANAGE_CMD_UPLOAD    : yes
 * RAMANAGE_UPLOAD_MAX_KB : 100
 * NOT_A_QWORD            : 0
 * PSPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\QoSient\ArgusClients\ramanage
 * PSParentPath           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\QoSient\ArgusClients
 * PSChildName            : ramanage
 * PSDrive                : HKLM
 * PSProvider             : Microsoft.PowerShell.Core\Registry
 *
 *
 * PS C:\Users\ekinzie> (Get-Item HKLM:\SOFTWARE\QoSient\ArgusClients\ramanage).GetValueKind('RAMANAGE_CMD_UPLOAD')
 * String
 * PS C:\Users\ekinzie> (Get-Item HKLM:\SOFTWARE\QoSient\ArgusClients\ramanage).GetValueKind('RAMANAGE_UPLOAD_MAX_KB')
 * QWord
 * PS C:\Users\ekinzie> (Get-Item HKLM:\SOFTWARE\QoSient\ArgusClients\ramanage).GetValueKind('NOT_A_QWORD')
 * DWord
 *
 */

# include <stdio.h>
int main(void) {
   char str[64];
   int i;
   HKEY handle;
   long long qword;

   if (ArgusWindowsRegistryOpenKey(ARGUS_CLIENTS_REGISTRY_HKEY,
                                   ARGUS_CLIENTS_REGISTRY_KEYNAME "\\ramanage",
                                   &handle) != 0) {
      printf("Unable to open registry key\n");
      fflush(stdout);
      return 1;
   }

   i = ArgusWindowsRegistryGetSZ(handle, "RAMANAGE_CMD_UPLOAD", str, sizeof(str));
   if (i == 0)
      printf("Read %s from %s\\ramanage\\%s\n", str,
             ARGUS_CLIENTS_REGISTRY_KEYNAME, "RAMANAGE_CMD_UPLOAD");

   i = ArgusWindowsRegistryGetQWORD(handle, "RAMANAGE_UPLOAD_MAX_KB", &qword);
   if (i == 0)
      printf("Read %lld from %s\\ramanage\\%s\n", qword,
             ARGUS_CLIENTS_REGISTRY_KEYNAME, "RAMANAGE_UPLOAD_MAX_KB");

   i = ArgusWindowsRegistryGetQWORD(handle, "NOT_A_QWORD", &qword);
   if (i == 0)
      printf("Read %lld from %s\\ramanage\\%s????\n", qword,
             ARGUS_CLIENTS_REGISTRY_KEYNAME, "NOT_A_QWORD");
   else if (i < 0)
      printf("Found a type other than QWORD\n");


   ArgusWindowsRegistryCloseKey(handle);

   fflush(stdout);
   return 0;
}
#endif
