/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2026 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include <stdlib.h>
#include <string.h>
#include "serialize.h"

#ifndef CLI__SBOMTOOL__SPDX2__STRUCTURE_H
#define CLI__SBOMTOOL__SPDX2__STRUCTURE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SPDX2_SPECVERSION "2.2"

pkgconfcli_serialize_value_t *
sbomtool_spdx2_structure_new(pkgconf_client_t *client, const char *document_name, const char *document_license, const char *document_namespace);

bool
sbomtool_spdx2_structure_creation_info(pkgconf_client_t *client, pkgconfcli_serialize_value_t *spdx_doc, const char *timestamp, const char *manufacturer_name, const char *manufacturer_url, bool add_tool);

char*
sbomtool_spdx2_structure_creator(pkgconf_client_t *client, const char *type, const char *creator);



#ifdef __cplusplus
}
#endif

#endif
