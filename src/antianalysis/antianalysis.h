// src/antianalysis/antianalysis.h
#ifndef BLINDSPOT_ANTIANALYSIS_H
#define BLINDSPOT_ANTIANALYSIS_H

#include "../common/types.h"

// Общая проверка: TRUE_ = плохая среда, надо выходить.
BOOL_ anti_analysis_check(void);

BOOL_ is_debugger_present(void);
BOOL_ is_vm(void);
BOOL_ is_sandbox(void);

typedef struct {
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
} cpuid_result_t;

void cpu_id(u32 leaf, u32 subleaf, cpuid_result_t* out);

#endif