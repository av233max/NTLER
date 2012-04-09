
#define    VER_WIN2K                     0x00050000
#define    VER_WINXP                     0x00050001
#define    VER_WIN2K3                    0x80050002
#define    VER_VISTA                     0x00060000
#define    VER_WIN2K8                    0x80060000
#define    VER_WIN2K8R2                  0x80060001
#define    VER_WIN7                      0x00060001

#define    MU_PATCH_FILE_VERSION           20001

#define    MASK_PASS                       0

typedef BOOL (WINAPI *WINAPI_IsWow64Process) (
  HANDLE hProcess,
  PBOOL Wow64Process
);

#define    VER_NT_WORKSTATION            0x01

typedef struct _OSVERSIONINFOEX_ {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  TCHAR szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
}OSVERSIONINFOEX_, *POSVERSIONINFOEX_, *LPOSVERSIONINFOEX_;

int
ForceCopy (
    PWSTR ToPath,
    PWSTR FromPath
);

int
UpdateRegistry (
    HKEY MainKey
);

int
Update (
    int Version,
    HKEY MainKey
);

DWORD
InstallService (
    LPTSTR pszServiceName,
    LPTSTR pszFilePath,
    LPTSTR pszGroup,
    DWORD dwType,
    DWORD dwStart
);

int
Startup (
    void
);

int
UninstallService (
    LPTSTR pszServiceName
);

int
Install (
    void
);

int
Uninstall (
    BOOLEAN Silent
);

BOOLEAN
CheckOS (
    void
);

BOOLEAN
CheckStackFrame (
    PVOID RoutineEntry
);