#if defined(__CYGWIN__) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
# include <windows.h>
# include <sys/types.h>

# define ARGUS_CLIENTS_REGISTRY_HKEY HKEY_LOCAL_MACHINE
# define ARGUS_CLIENTS_REGISTRY_KEYNAME "SOFTWARE\\QoSient\\ArgusClients"

int ArgusWindowsRegistryOpenKey(HKEY, const char * const, HKEY *);
int ArgusWindowsRegistryCloseKey(HKEY);
int ArgusWindowsRegistryGetQWORD(HKEY, const char * const, long long *);
int ArgusWindowsRegistryGetSZ(HKEY, const char * const, char *, size_t);
#endif /* CYGWIN, _MSC_VER, . . . */
