/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2025 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include <libpkgconfcli/serialize.h>
#include "spdx3/simplelicensing.h"
#include "util.h"


/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx3_simplelicensing_licenseExpression_to_object(const char *creation_info, const spdxtool_simplelicensing_license_expression_t *expression)
 *
 *    Serialize /SimpleLicensing/LicenseExpression struct to a JSON value tree.
 *
 *    :param const char *creation_info: The creationInfo ID string to embed in the object.
 *    :param const sbomtool_spdx3_simplelicensing_license_expression_t *expression: LicenseExpression struct to be serialized.
 *    :return: pkgconfcli_serialize_value_t * representing the LicenseExpression object.
 */
pkgconfcli_serialize_value_t *
sbomtool_spdx3_simplelicensing_licenseExpression(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, const char *spdx_expression)
{
	pkgconfcli_serialize_value_t *ret = NULL;
	pkgconfcli_serialize_object_list_t *object_list = pkgconfcli_serialize_object_list_new();
	char *spdx_id = sbomtool_util_get_sbom_id_string(client, "simplelicensing_LicenseExpression", spdx_expression);

	if (!object_list || !spdx_id)
	{
		goto err;
	}

	if (!(pkgconfcli_serialize_object_add_string(object_list, "type", "simplelicensing_LicenseExpression") &&
		pkgconfcli_serialize_object_add_string(object_list, "creationInfo", document->creation_info_id) &&
		pkgconfcli_serialize_object_add_string(object_list, "spdxId", spdx_id) &&
		pkgconfcli_serialize_object_add_string(object_list, "simplelicensing_licenseExpression", spdx_expression)))
	{
		goto err;
	}

	ret = pkgconfcli_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx3_simplelicensing_licenseExpression_to_object: out of memory");

	free(spdx_id);

	pkgconfcli_serialize_object_list_free(object_list);
	return ret;
}
