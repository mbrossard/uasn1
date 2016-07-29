#ifndef OIDS_H
#define OIDS_H

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "uasn1.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Look-up name in OID database
 * @param [in] name Pointer to <tt>NULL</tt>-terminated string
 * @returns Pointer to uasn1_item_t structure if found
 * @returns @c NULL otherwise
 */
uasn1_item_t *uasn1_get_oid_by_name(char *name);

/**
 * @brief Look-up OID in database
 * @param [in] name Pointer to uasn1_item_t structure.
 * @returns Pointer to <tt>NULL</tt>-terminated string if found
 * @returns @c NULL otherwise
 */
char *uasn1_get_oid(uasn1_item_t *oid);


typedef struct
{
  char *name;
  unsigned int size;
  unsigned char *oid;
} oidelement;

extern unsigned char oids[];
extern oidelement oidtable[];


#endif
