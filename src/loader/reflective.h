// src/loader/reflective.h
#ifndef BLINDSPOT_REFLECTIVE_H
#define BLINDSPOT_REFLECTIVE_H

#include "../common/types.h"

// Reflective-загрузка PE в память.
//
// raw_pe        — указатель на PE-образ в памяти (как файл на диске)
// raw_size      — размер PE-образа
// desired_base  — желаемый адрес размещения (0 = любой)
//
// Возвращает указатель на entry point PE в памяти или NULL_ при ошибке.
// Если нужен указатель на базу загруженного образа — пишем в out_base.
void* reflective_load(u8* raw_pe, u32 raw_size, u64 desired_base, void** out_base);

#endif