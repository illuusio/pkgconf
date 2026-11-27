/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2026 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include "serialize.h"


#ifndef CLI__SBOMTOOL__SPDX2__COMPONENT_H
#define CLI__SBOMTOOL__SPDX2__COMPONENT_H

#ifdef __cplusplus
extern "C" {
#endif

pkgconfcli_serialize_value_t *
sbomtool_spdx2_package_new(pkgconf_client_t *client, const char *name, const char *version);

bool
sbomtool_spdx2_component_add_license(pkgconf_client_t *client, pkgconfcli_serialize_array_t *licenses, const char *id);

void
sbomtool_spdx2_package_add_package(pkgconf_client_t *client, pkgconf_pkg_t *pkg, void *ptr, unsigned int iter_flags);

#ifdef __cplusplus
}
#endif

#endif
