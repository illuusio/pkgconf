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


#ifndef CLI__SBOMTOOL__SPDX2__RELATIONSHIP_H
#define CLI__SBOMTOOL__SPDX2__RELATIONSHIP_H

#ifdef __cplusplus
extern "C" {
#endif

pkgconfcli_serialize_value_t *
sbomtool_spdx2_relationship_new(pkgconf_client_t *client, const char *from, const char *to, const char *type);

#ifdef __cplusplus
}
#endif

#endif
