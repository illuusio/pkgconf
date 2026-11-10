/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2025 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#ifndef CLI__SBOMTOOL__SPDX3__CORE_H
#define CLI__SBOMTOOL__SPDX3__CORE_H

#include <stdlib.h>
#include "util.h"
#include "serialize.h"
#include "spdx3/structure.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPDX3_SPECVERSION "3.0.1"

pkgconfcli_serialize_value_t *
sbomtool_spdx3_core_agent(pkgconf_client_t *client, const char *creation_info_id, const char *name);

pkgconfcli_serialize_value_t *
sbomtool_spdx3_core_tool(pkgconf_client_t *client, const char *creation_info_id, const char *short_name, const char *name);

pkgconfcli_serialize_value_t *
sbomtool_spdx3_core_creation_info(pkgconf_client_t *client, const char *agent_id, const char *tool_id, const char *id, const char *time);

/*bool
sbomtool_spdx3_core_spdx_document_is_license(pkgconf_client_t *client, const spdxtool_core_spdx_document_t *spdx, const char *license);

bool
sbomtool_spdx3_core_spdx_document_add_license(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx, const char *license);

bool
sbomtool_spdx3_core_spdx_document_add_relationship(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx, spdxtool_core_relationship_t *relationship);

bool
sbomtool_spdx3_core_spdx_document_add_package(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx, pkgconf_pkg_t *pkg);

bool
sbomtool_spdx3_core_spdx_document_add_element(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx, const char *element);

const char *
sbomtool_spdx3_core_spdx_document_add_maintainer(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx, const char *name);

pkgconfcli_serialize_value_t *
sbomtool_spdx3_core_spdx_document_to_object(pkgconf_client_t *client, spdxtool_core_spdx_document_t *spdx);

bool
sbomtool_spdx3_core_relationship_set_scope(pkgconf_client_t *client, spdxtool_core_relationship_t *relationship, const char *scope);
*/
pkgconfcli_serialize_value_t *
sbomtool_core_relationship(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, const char *from, pkgconfcli_serialize_array_t *to, const char *name, const char *relationship_type, const char *scope);

#ifdef __cplusplus
}
#endif

#endif
