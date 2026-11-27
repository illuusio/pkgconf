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

#ifndef CLI__SBOMTOOL__SPDX2__SDPX_H
#define CLI__SBOMTOOL__SPDX2__SPDX_H

#ifdef __cplusplus
extern "C" {
#endif

bool
sbomtool_spdx2_spdx_value_to_buf(pkgconf_buffer_t *buffer, pkgconfcli_serialize_value_t *value);

#ifdef __cplusplus
}
#endif

#endif
