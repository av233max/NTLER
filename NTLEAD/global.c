#include <ntddk.h>

#include "ntlead.h"

ULONG OsVersion;

MU_GLOBAL_DATA g_GlobalData;

NTUNEXPPROC_RtlInitNlsTables     RtlInitNlsTables;
NTUNEXPPROC_MmCreatePeb          MmCreatePeb;
NTUNEXPPROC_MmCreateTeb          MmCreateTeb;
NTUNEXPPROC_MmGetSessionLocaleId MmGetSessionLocaleId;
NTUNEXPPROC_NtQueryDefaultLocale NtQueryDefaultLocale;
NTUNEXPPROC_NtQueryDefaultUILanguage NtQueryDefaultUILanguage;
NTUNEXPPROC_NtQueryInstallUILanguage NtQueryInstallUILanguage;

NTPROC_NtCreateFile NtCreateFile_;
NTPROC_NtOpenFile NtOpenFile_;

PVOID ObOpenObjectByName_;

WCHAR Unicode_Katakana_Gothic[] = {
    0xFF7A, 0xFF9E, 0xFF7C, 0xFF6F, 0xFF78, 0x0000
};

WCHAR Unicode_Katakana_Courier[] = {
    0xFF78, 0xFF70, 0xFF98, 0xFF74, 0x0000
};

WCHAR Unicode_Katakana_Arial[] = {
    0xFF8D, 0xFF99, 0xFF8D, 0xFF9E, 0xFF81, 0xFF76, 0x0000
};

WCHAR Unicode_Katakana_TimesNewRoman[] = {
    0xFF80, 0xFF72, 0xFF91, 0xFF7D, 0xFF9E, 0xFF9B, 0xFF8F, 0xFF9D, 0x0000
};

//Substitutes_NT5_JAP

MUALIGN MU_SUBSITUTES_META_DATA SMD_NT5_JAP_0 = {
    L"Tahoma",
    L"MS UI Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_1 = {
    L"Lucida Sans Unicode",
    L"MS UI Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_2 = {
    L"Microsoft Sans Serif",
    L"MS UI Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_3 = {
    Unicode_Katakana_Gothic,
    L"MS Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_4 = {
    Unicode_Katakana_Courier,
    L"Courier"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_5 = {
    Unicode_Katakana_Arial,
    L"Arial"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_6 = {
    Unicode_Katakana_TimesNewRoman,
    L"Times New Roman"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_7 = {
    L"ゴシック",
    L"MS Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_8 = {
    L"ＭＳ ゴシック",
    L"MS Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_9 = {
    L"ＭＳ Ｐゴシック",
    L"MS PGothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_10 = {
    L"標準ゴシック",
    L"MS Gothic"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_11 = {
    L"ＭＳ 明朝",
    L"MS Mincho"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_12 = {
    L"ＭＳ Ｐ明朝",
    L"MS PMincho"
};

MU_SUBSITUTES_META_DATA SMD_NT5_JAP_13 = {
    L"標準明朝",
    L"MS Mincho"
};

//End

//Substitutes_NT5_CHS

MU_SUBSITUTES_META_DATA SMD_NT5_CHS_0 = {
    L"Tahoma",
    L"SimSun"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHS_1 = {
    L"Lucida Sans Unicode",
    L"SimSun"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHS_2 = {
    L"Microsoft Sans Serif",
    L"SimSun"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHS_3 = {
    L"宋体",
    L"SimSun"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHS_4 = {
    L"新宋体",
    L"SimSun"
};

//End

//Substitutes_NT5_CHT

MU_SUBSITUTES_META_DATA SMD_NT5_CHT_0 = {
    L"Tahoma",
    L"PMingLiU"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHT_1 = {
    L"Lucida Sans Unicode",
    L"PMingLiU"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHT_2 = {
    L"Microsoft Sans Serif",
    L"PMingLiU"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHT_3 = {
    L"細明體",
    L"PMingLiU"
};

MU_SUBSITUTES_META_DATA SMD_NT5_CHT_4 = {
    L"新細明體",
    L"PMingLiU"
};

//End

//LSD_NT5

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_0411_0 = {
    0x411,
    14,
    &SMD_NT5_JAP_0
};

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_0804_1 = {
    0x804,
    5,
    &SMD_NT5_CHS_0
};

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_1004_2 = {
    0x1004,
    5,
    &SMD_NT5_CHS_0
};

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_0404_3 = {
    0x404,
    5,
    &SMD_NT5_CHT_0
};

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_0C04_4 = {
    0xC04,
    5,
    &SMD_NT5_CHT_0
};

MU_LOCALE_SUBSITUTES_DESCRIPTOR LSD_NT5_1404_5 = {
    0x1404,
    5,
    &SMD_NT5_CHT_0
};

//End

//VxXP

UCHAR VCXP_MmCreatePeb[] = {
    0x8D, 0x83, 0xB0, 0x01, 0x00, 0x00, 0x50, 0x8D, 0x45, 0xC0, 0x50, 0x53, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0xF8, 0x3B, 0xFE
};

UCHAR VMXP_MmCreatePeb[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0
};

UCHAR VCXP_MmGetSessionLocaleId[] = {
    0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x8B, 0xD8, 0x83, 0x65, 0xFC, 0x00, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x89, 0x83, 0xC4, 0x00, 0x00, 0x00
};

UCHAR VMXP_MmGetSessionLocaleId[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
};

UCHAR VCXP_RtlInitNlsTables[] = {
    0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x14, 0x8D, 0x46, 0x2C, 0x50, 0xFF, 0x75, 0x08, 0xE8
};

UCHAR VMXP_RtlInitNlsTables[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

UCHAR VCXP_LdrpWalkImportDescriptor_0[] = {
    0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, 0xF7, 0xC1, 0x00, 0x00, 0x40, 0x00, 0x75, 0x18, 0x50, 0xFF, 0xB5, 0xB8, 0xFD, 0xFF, 0xFF, 0xE8
};

UCHAR VMXP_LdrpWalkImportDescriptor_0[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

UCHAR VCXP_LdrpWalkImportDescriptor_1[] = {
    0xFF, 0x36, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0xFF, 0x36, 0xFF, 0xB5, 0xEC, 0xFD, 0xFF, 0xFF, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0xF8, 0x85, 0xFF
};

UCHAR VMXP_LdrpWalkImportDescriptor_1[] = {
    0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0
};

UCHAR VCXP_LdrpWalkImportDescriptor_2[] = {
    0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x3B, 0xC7, 0x89, 0x45, 0x98, 0x0F, 0x8C, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0x7B, 0x08, 0x8B, 0x85, 0x64, 0xFF, 0xFF, 0xFF
};

UCHAR VMXP_LdrpWalkImportDescriptor_2[] = {
    0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//End

//Vx2K3

UCHAR VC2K3_MmCreatePeb[] = {
    0x8D, 0x83, 0xA0, 0x01, 0x00, 0x00, 0x50, 0x8D, 0x45, 0xC4, 0x50, 0x53, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0xF8, 0x85, 0xFF
};

UCHAR VM2K3_MmCreatePeb[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0
};

UCHAR VC2K3_MmGetSessionLocaleId[] = {
    0x64, 0x8B, 0x3D, 0x18, 0x00, 0x00, 0x00, 0x38, 0x5D, 0xE7, 0x75, MASK_PASS, 0x89, 0x5D, 0xFC, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x89, 0x87, 0xC4, 0x00, 0x00, 0x00
};

UCHAR VM2K3_MmGetSessionLocaleId[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
};

UCHAR VC2K3_LdrpWalkImportDescriptor_0[] = {
    0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, 0xF7, 0xC1, 0x00, 0x00, 0x40, 0x00, 0x75, 0x13, 0x50, 0x57, 0xE8
};

UCHAR VM2K3_LdrpWalkImportDescriptor_0[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

UCHAR VC2K3_LdrpWalkImportDescriptor_1[] = {
    0xFF, 0x36, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0xFF, 0x36, 0x57, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0xD8, 0x85, 0xDB, 0x0F, 0x8D
};

UCHAR VM2K3_LdrpWalkImportDescriptor_1[] = {
    0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
};

UCHAR VC2K3_LdrpWalkImportDescriptor_2[] = {
    0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0xF0, 0x85, 0xF6, 0x0F, 0x8C, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x8B, 0x73, 0x08, 0x8B, 0x45, 0x90, 0x39, 0x70, 0x34
};

UCHAR VM2K3_LdrpWalkImportDescriptor_2[] = {
    0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//End

//VxW7

UCHAR VCW7_MmCreatePeb[] = {
    0x8D, 0xB3, 0xA8, 0x01, 0x00, 0x00, 0x8D, 0x45, 0xD8, 0x50, 0x56, 0x53, 0x8D, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x89, 0x45, 0xD4, 0x85, 0xC0
};

UCHAR VMW7_MmCreatePeb[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0
};

UCHAR VCW7_MmGetSessionLocaleId[] = {
    0x8B, 0x77, 0x50, 0x89, 0x75, 0xE0, 0x8B, 0x97, 0x88, 0x00, 0x00, 0x00, 0x89, 0x5D, 0xFC, 0xE8, MASK_PASS, MASK_PASS, MASK_PASS, MASK_PASS, 0x89, 0x82, 0xC4, 0x00, 0x00, 0x00
};

UCHAR VMW7_MmGetSessionLocaleId[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
};

//End

//VDXP

MUALIGN MU_VERIFY_DATA VerifyData_NtKernel_Export_WINXP_0 = {
    NULL,
    sizeof(VCXP_RtlInitNlsTables),
    VCXP_RtlInitNlsTables,
    VMXP_RtlInitNlsTables,
    0
};

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WINXP_1 = {
    NULL,
    sizeof(VCXP_MmGetSessionLocaleId),
    VCXP_MmGetSessionLocaleId,
    VMXP_MmGetSessionLocaleId,
    13
};

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WINXP_0 = {
    &VerifyData_NtKernel_Hook_WINXP_1,
    sizeof(VCXP_MmCreatePeb),
    VCXP_MmCreatePeb,
    VMXP_MmCreatePeb,
    13
};

MU_VERIFY_DATA VerifyData_NtDll_WINXP_2 = {
    NULL,
    sizeof(VCXP_LdrpWalkImportDescriptor_2),
    VCXP_LdrpWalkImportDescriptor_2,
    VMXP_LdrpWalkImportDescriptor_2,
    1
};

MU_VERIFY_DATA VerifyData_NtDll_WINXP_1 = {
    &VerifyData_NtDll_WINXP_2,
    sizeof(VCXP_LdrpWalkImportDescriptor_1),
    VCXP_LdrpWalkImportDescriptor_1,
    VMXP_LdrpWalkImportDescriptor_1,
    16
};

MU_VERIFY_DATA VerifyData_NtDll_WINXP_0 = {
    &VerifyData_NtDll_WINXP_1,
    sizeof(VCXP_LdrpWalkImportDescriptor_0),
    VCXP_LdrpWalkImportDescriptor_0,
    VMXP_LdrpWalkImportDescriptor_0,
    sizeof(VCXP_LdrpWalkImportDescriptor_0)
};

//End

//VD2K3

MU_VERIFY_DATA VerifyData_NtKernel_Export_WIN2K3_0 = {
    NULL,
    sizeof(VCXP_RtlInitNlsTables),
    VCXP_RtlInitNlsTables,
    VMXP_RtlInitNlsTables,
    0
};

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN2K3_1 = {
    NULL,
    sizeof(VC2K3_MmGetSessionLocaleId),
    VC2K3_MmGetSessionLocaleId,
    VM2K3_MmGetSessionLocaleId,
    16
};

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN2K3_0 = {
    &VerifyData_NtKernel_Hook_WIN2K3_1,
    sizeof(VC2K3_MmCreatePeb),
    VC2K3_MmCreatePeb,
    VM2K3_MmCreatePeb,
    13
};

MU_VERIFY_DATA VerifyData_NtDll_WIN2K3_2 = {
    NULL,
    sizeof(VC2K3_LdrpWalkImportDescriptor_2),
    VC2K3_LdrpWalkImportDescriptor_2,
    VM2K3_LdrpWalkImportDescriptor_2,
    1
};

MU_VERIFY_DATA VerifyData_NtDll_WIN2K3_1 = {
    &VerifyData_NtDll_WIN2K3_2,
    sizeof(VC2K3_LdrpWalkImportDescriptor_1),
    VC2K3_LdrpWalkImportDescriptor_1,
    VM2K3_LdrpWalkImportDescriptor_1,
    11
};

MU_VERIFY_DATA VerifyData_NtDll_WIN2K3_0 = {
    &VerifyData_NtDll_WIN2K3_1,
    sizeof(VC2K3_LdrpWalkImportDescriptor_0),
    VC2K3_LdrpWalkImportDescriptor_0,
    VM2K3_LdrpWalkImportDescriptor_0,
    sizeof(VC2K3_LdrpWalkImportDescriptor_0)
};

//End

//VDW7

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN7_1 = {
    NULL,
    sizeof(VCW7_MmGetSessionLocaleId),
    VCW7_MmGetSessionLocaleId,
    VMW7_MmGetSessionLocaleId,
    16
};

MU_VERIFY_DATA VerifyData_NtKernel_Hook_WIN7_0 = {
    &VerifyData_NtKernel_Hook_WIN7_1,
    sizeof(VCW7_MmCreatePeb),
    VCW7_MmCreatePeb,
    VMW7_MmCreatePeb,
    19
};

//END

//Dummy

MUALIGN MU_HOOK_CALL_BLOCK HBXP_NtKernel_0 = {
    0x0,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_NtKernel_1 = {
    0x0,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_NtKernel_0 = {
    0x0,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

MUALIGN MU_AUDIT_BLOCK ABXP_NtKernel_Export = {
    1,
    NULL,
    (PMU_PUBLIC_BLOCK)&LBXP_NtKernel_0
};

MUALIGN MU_AUDIT_BLOCK ABXP_NtKernel_Hook = {
    2,
    NULL,
    (PMU_PUBLIC_BLOCK)&HBXP_NtKernel_0
};

//End

//VBXP_Ntdll_2180

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_2180_0 = {
    0x16085,
    5,
    {0xE8, 0xCC, 0x68, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_2180_1 = {
    0x1DE84,
    5,
    {0xE8, 0xCD, 0xEA, 0xFF, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_2180_2 = {
    0x2234F,
    5,
    {0xE8, 0x34, 0x78, 0xFF, 0xFF}
};

//End

//RBXP_Ntdll_2180

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_2180_0 = {
    0x160C0,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_2180_1 = {
    0x1DE92,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_2180_2 = {
    0x2236C,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

//End

//VBXP_Ntdll_5512

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_5512_0 = {
    0x16298,
    5,
    {0xE8, 0x14, 0x5E, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_5512_1 = {
    0x1D7C1,
    5,
    {0xE8, 0xEB, 0xE8, 0xFF, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntdll_5512_2 = {
    0x21E20,
    5,
    {0xE8, 0x8C, 0xA2, 0xFF, 0xFF}
};

//End

//RBXP_Ntdll_5512

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_5512_0 = {
    0x16299,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_5512_1 = {
    0x1D7C2,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBXP_Ntdll_5512_2 = {
    0x21E21,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

//End

//ABXP_Ntdll_2180

MUALIGN MU_AUDIT_BLOCK ABXP_Ntdll_2180_0 = {
    3,
    &VBXP_Ntdll_2180_0,
    (PMU_PUBLIC_BLOCK)&RBXP_Ntdll_2180_0
};


MUALIGN MU_AUDIT_BLOCK ABXP_Ntdll_5512_1 = {
    3,
    &VBXP_Ntdll_5512_0,
    (PMU_PUBLIC_BLOCK)&RBXP_Ntdll_5512_0
};

//End

//VBW6_Ntdll_18000

MUALIGN MU_VERIFY_BLOCK VBW6_Ntdll_18000_0 = {
    0x2C578,
    5,
    {0xE8, 0x56, 0x12, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBW6_Ntdll_18000_1 = {
    0x2FACD,
    5,
    {0xE8, 0x01, 0xDD, 0xFF, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBW6_Ntdll_18000_2 = {
    0x30FBD,
    5,
    {0xE8, 0x47, 0x3F, 0x01, 0x00}
};

//End

//RBW6_Ntdll_18000

MUALIGN MU_REPLACE_CALL_BLOCK RBW6_Ntdll_18000_0 = {
    0x2C5B6,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBW6_Ntdll_18000_1 = {
    0x2FADB,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

MUALIGN MU_REPLACE_CALL_BLOCK RBW6_Ntdll_18000_2 = {
    0x30FDF,
    OP_REPLACE_CALL,
    &g_GlobalData.DllEntries.MuOrgWalkImportDescriptor,
    &g_GlobalData.DllEntries.MuHookWalkImportDescriptor
};

//End

//ABW6_Ntdll_18000

MUALIGN MU_AUDIT_BLOCK ABW6_Ntdll_18000_0 = {
    3,
    &VBW6_Ntdll_18000_0,
    (PMU_PUBLIC_BLOCK)&RBW6_Ntdll_18000_0
};

//End

//xBXP_Ntoskrnl_2180

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntoskrnl_2180_0 = {
    0xB1CD4,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntoskrnl_2180_1 = {
    0xA85C9,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntoskrnl_2180_2 = {
    0xFAFEB,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};
//End

//VBXP_Ntoskrnl_2180

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_2180_0 = {
    0xB1CD3,
    5,
    {0xE8, 0x2C, 0x0D, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_2180_1 = {
    0xA85C8,
    5,
    {0xE8, 0x01, 0x72, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_2180_2 = {
    0xFAFFB,
    5,
    {0xE8, 0x1C, 0x00, 0x00, 0x00}
};

//End

//xBXP_Ntkrnlpa_2180

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlpa_2180_0 = {
    0xEE89D,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlpa_2180_1 = {
    0xED8DD,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrnlpa_2180_2 = {
    0xF905E,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrnlpa_2180

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_2180_0 = {
    0xEE89C,
    5,
    {0xE8, 0xC3, 0xE2, 0xFD, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_2180_1 = {
    0xED8DC,
    5,
    {0xE8, 0xBD, 0x3B, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_2180_2 = {
    0xF906E,
    5,
    {0xE8, 0x19, 0xFF, 0xFF, 0xFF}
};

//End

//xBXP_Ntkrnlmp_2180

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlmp_2180_0 = {
    0xB43F2,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlmp_2180_1 = {
    0xAFEBA,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrnlmp_2180_2 = {
    0xF366D,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrnlmp_2180

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_2180_0 = {
    0xB43F1,
    5,
    {0xE8, 0x6B, 0x06, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_2180_1 = {
    0xAFEB9,
    5,
    {0xE8, 0x1E, 0x96, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_2180_2 = {
    0xF367D,
    5,
    {0xE8, 0x1C, 0x00, 0x00, 0x00}
};

//End

//xBXP_Ntkrpamp_2180

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrpamp_2180_0 = {
    0xF85D1,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrpamp_2180_1 = {
    0xF7651,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrpamp_2180_2 = {
    0x102CD4,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrpamp_2180

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_2180_0 = {
    0xF85D0,
    5,
    {0xE8, 0x29, 0xEF, 0xFD, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_2180_1 = {
    0xF7650,
    5,
    {0xE8, 0xAE, 0x48, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_2180_2 = {
    0x102CE4,
    5,
    {0xE8, 0x19, 0xFF, 0xFF, 0xFF}
};

//End

//xBXP_Ntoskrnl_5512

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntoskrnl_5512_0 = {
    0xA95EB,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntoskrnl_5512_1 = {
    0xB79A6,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntoskrnl_5512_2 = {
    0xFA037,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};
//End

//VBXP_Ntoskrnl_5512

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_5512_0 = {
    0xA95EA,
    5,
    {0xE8, 0xF9, 0x05, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_5512_1 = {
    0xB79A5,
    5,
    {0xE8, 0x54, 0x82, 0xFD, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntoskrnl_5512_2 = {
    0xFA047,
    5,
    {0xE8, 0x1C, 0x00, 0x00, 0x00}
};

//End

//xBXP_Ntkrnlpa_5512

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlpa_5512_0 = {
    0xEFFD5,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlpa_5512_1 = {
    0xEF015,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrnlpa_5512_2 = {
    0xFA7EC,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrnlpa_5512

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_5512_0 = {
    0xEFFD4,
    5,
    {0xE8, 0xAB, 0xE0, 0xFD, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_5512_1 = {
    0xEF014,
    5,
    {0xE8, 0xAB, 0x39, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlpa_5512_2 = {
    0xFA7FC,
    5,
    {0xE8, 0x19, 0xFF, 0xFF, 0xFF}
};

//End

//xBXP_Ntkrnlmp_5512

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlmp_5512_0 = {
    0xB45D3,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrnlmp_5512_1 = {
    0xAFE17,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrnlmp_5512_2 = {
    0xF02AE,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrnlmp_5512

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_5512_0 = {
    0xB45D2,
    5,
    {0xE8, 0x23, 0x11, 0x00, 0x00}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_5512_1 = {
    0xAFE16,
    5,
    {0xE8, 0x18, 0x83, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrnlmp_5512_2 = {
    0xF02BE,
    5,
    {0xE8, 0x1C, 0x00, 0x00, 0x00}
};

//End

//xBXP_Ntkrpamp_5512

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrpamp_5512_0 = {
    0xF9DA1,
    OP_HOOK_CALL,
    (PVOID *)&MmCreatePeb,
    MuCreatePeb
};

MUALIGN MU_HOOK_CALL_BLOCK HBXP_Ntkrpamp_5512_1 = {
    0xF8E21,
    OP_HOOK_CALL,
    (PVOID *)&MmGetSessionLocaleId,
    MuGetSessionLocaleId
};

MUALIGN MU_LOCATE_ENTRY_BLOCK LBXP_Ntkrpamp_5512_2 = {
    0x10452E,
    OP_LOCATE_ENTRY,
    (PVOID *)&RtlInitNlsTables
};

//End

//VBXP_Ntkrpamp_5512

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_5512_0 = {
    0xF9DA0,
    5,
    {0xE8, 0x8B, 0xED, 0xFD, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_5512_1 = {
    0xF8E20,
    5,
    {0xE8, 0x17, 0x47, 0xFE, 0xFF}
};

MUALIGN MU_VERIFY_BLOCK VBXP_Ntkrpamp_5512_2 = {
    0x10453E,
    5,
    {0xE8, 0x19, 0xFF, 0xFF, 0xFF}
};

//End

//ABXP_Ntoskrnl

MUALIGN MU_AUDIT_BLOCK ABXP_Ntoskrnl_2180_0 = {
    3,
    &VBXP_Ntoskrnl_2180_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntoskrnl_2180_0
};

MUALIGN MU_AUDIT_BLOCK ABXP_Ntoskrnl_5512_0 = {
    3,
    &VBXP_Ntoskrnl_5512_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntoskrnl_5512_0
};

//End

//ABXP_Ntkrnlpa

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrnlpa_2180_0 = {
    3,
    &VBXP_Ntkrnlpa_2180_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrnlpa_2180_0
};

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrnlpa_5512_0 = {
    3,
    &VBXP_Ntkrnlpa_5512_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrnlpa_5512_0
};

//End

//ABXP_Ntkrnlmp

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrnlmp_2180_0 = {
    3,
    &VBXP_Ntkrnlmp_2180_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrnlmp_2180_0
};

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrnlmp_5512_0 = {
    3,
    &VBXP_Ntkrnlmp_5512_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrnlmp_5512_0
};

//End

//ABXP_Ntkrpamp

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrpamp_2180_0 = {
    3,
    &VBXP_Ntkrpamp_2180_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrpamp_2180_0
};

MUALIGN MU_AUDIT_BLOCK ABXP_Ntkrpamp_5512_0 = {
    3,
    &VBXP_Ntkrpamp_5512_0,
    (PMU_PUBLIC_BLOCK)&HBXP_Ntkrpamp_5512_0
};

//End

MU_NTKERNEL_HOOK_DATA HookData_WINXP = {
    2,
    {
        &ABXP_Ntoskrnl_2180_0,
        &ABXP_Ntkrnlpa_2180_0,
        &ABXP_Ntkrnlmp_2180_0,
        &ABXP_Ntkrpamp_2180_0
    }
};


DEFINE_GUID(MuKnownDatabaseGuid,
0xeed0816d, 0xacbb, 0x4f9c, 0xb5, 0x3a, 0x26, 0x4f, 0xcd, 0xf2, 0xd2, 0x25);

DEFINE_GUID(MuPrivateDatabaseGuid,
0xda8a46f0, 0xcae2, 0x41b5, 0x81, 0x88, 0x68, 0x5f, 0x72, 0xe3, 0xba, 0xfb);


PMU_GLOBAL_DATA
MuAcquireGlobalLock (
    PKLOCK_QUEUE_HANDLE LockHandle
)
{
    KeAcquireInStackQueuedSpinLock(&g_GlobalData.GlobalLock, LockHandle);
    
    return &g_GlobalData;
}

PMU_GLOBAL_DATA
MuAcquireThreadRecordLock (
    PKLOCK_QUEUE_HANDLE LockHandle
)
{
    KeAcquireInStackQueuedSpinLock(&g_GlobalData.ThreadRecordLock, LockHandle);
    
    return &g_GlobalData;
}

PMU_GLOBAL_DATA
MuAcquireProcessContextLock (
    PKLOCK_QUEUE_HANDLE LockHandle
)
{
    KeAcquireInStackQueuedSpinLock(&g_GlobalData.ProcessContextLock, LockHandle);
    
    return &g_GlobalData;
}

PMU_GLOBAL_DATA
MuAcquireNsdLibraryMutex (
    void
)
{
    KeWaitForMutexObject(&g_GlobalData.NsdLibraryMutex,
                         Executive,
                         KernelMode,
                         FALSE,
                         NULL);
    
    return &g_GlobalData;
}

void
MuReleaseNsdLibraryMutex (
    void
)
{
    KeReleaseMutex(&g_GlobalData.NsdLibraryMutex, FALSE);
}

void
MuReleaseSpinLock (
    PKLOCK_QUEUE_HANDLE LockHandle
)
{
    KeReleaseInStackQueuedSpinLock(LockHandle);
}

PMU_GLOBAL_DATA
MuAcquireImpersonationPathMutex (
    void
)
{
    ExAcquireFastMutex(&g_GlobalData.ImpersonationPathMutex);
    
    return &g_GlobalData;
}

void
MuReleaseImpersonationPathMutex (
    void
)
{
    ExReleaseFastMutex(&g_GlobalData.ImpersonationPathMutex);
}

PMU_PROCESS_CONTEXT
MuCreateProcessContext (
    void
)
{
    PMU_PROCESS_CONTEXT node, newobj = (PMU_PROCESS_CONTEXT)MuAlloc(sizeof(MU_PROCESS_CONTEXT));
    KLOCK_QUEUE_HANDLE lock;
    
    if (newobj)
    {
        RtlZeroMemory(newobj, sizeof(MU_PROCESS_CONTEXT));
        
        newobj->RefCount = 1;
        
        MuAcquireProcessContextLock(&lock);
        
        node = g_GlobalData.ProcessContext;
        
        if (node)
        {
            while (node->Next)
                node = node->Next;
            
            node->Next = newobj;
        }
        else
        {
            g_GlobalData.ProcessContext = newobj;
        }
        
        MuReleaseSpinLock(&lock);
    }
    
    return newobj;
}

void
MuDereferenceProcessContext (
    PMU_PROCESS_CONTEXT Context
)
{
    PMU_PROCESS_CONTEXT previous = NULL, current;
    KLOCK_QUEUE_HANDLE lock;
    
    MuAcquireProcessContextLock(&lock);
    
    if (--Context->RefCount == 0)
    {
        current = g_GlobalData.ProcessContext;
        
        while (current)
        {
            if (current == Context)
            {
                if (previous)
                    previous->Next = current->Next;
                else
                    g_GlobalData.ProcessContext = current->Next;
                
                break;
            }
            
            previous = current;
            current  = current->Next;
        }
    }
    
    MuReleaseSpinLock(&lock);
}

PMU_PROCESS_CONTEXT
MuLookupCurrentProcessContext (
    void
)
{
    return MuLookupProcessContext(PsGetCurrentProcess());
}

PMU_PROCESS_CONTEXT
MuLookupProcessContext (
    PEPROCESS ProcessObject
)
{
    PMU_PROCESS_CONTEXT node = g_GlobalData.ProcessContext;
    KLOCK_QUEUE_HANDLE lock;
    
    MuAcquireProcessContextLock(&lock);
    
    while (node)
    {
        if (node->ProcessObject == ProcessObject)
        {
            node->RefCount++;
            
            break;
        }
        
        node = node->Next;
    }
    
    MuReleaseSpinLock(&lock);
    
    return node;
}

ULONG
MuLookupImpersonationPathByJackName (
    PWSTR Path
)
{
    ULONG count = 0;
    PMU_PATH_MAPPING_RECORD node = g_GlobalData.PathMappingRecord;
    
    while (node)
    {
        count++;
        
        if (!_wcsicmp(node->Path, Path))
            return count;
        
        node = node->Next;
    }
    
    return 0;
}

ULONG
MuAllocateAndInsertPathMappingObject (
    PWSTR Path
)
{
    ULONG count = 0;
    PMU_PATH_MAPPING_RECORD node, newobj = MuPagedAlloc(sizeof(MU_PATH_MAPPING_RECORD) + (wcslen(Path) * sizeof(WCHAR)));
    
    if (newobj)
    {
        newobj->Next = NULL;
        
        wcscpy(newobj->Path, Path);
        
        count++;
        
        node = g_GlobalData.PathMappingRecord;
        
        if (node)
        {
            count++;
            
            while (node->Next)
            {
                node = node->Next;
                
                count++;
            }
            
            node->Next = newobj;
        }
        else
        {
            g_GlobalData.PathMappingRecord = newobj;
        }
        
        g_GlobalData.MappedPathCount++;
    }
    
    return count;
}