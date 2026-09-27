// src/telemetry/amsi_patch.h
#ifndef BLINDSPOT_AMSI_PATCH_H
#define BLINDSPOT_AMSI_PATCH_H

#include "../common/types.h"

// Патч AMSI: AmsiScanBuffer → возвращает AMSI_RESULT_CLEAN (0).
// Возвращает TRUE_ если удалось (или AMSI не загружен — тоже ок).
BOOL_ patch_amsi(void);

#endif