// src/telemetry/etw_patch.h
#ifndef BLINDSPOT_ETW_PATCH_H
#define BLINDSPOT_ETW_PATCH_H

#include "../common/types.h"

// Патч ETW: EtwEventWrite → сразу ret.
BOOL_ patch_etw(void);

#endif