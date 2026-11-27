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
#include "libpkgconf/libpkgconf.h"
#include "spdx2/relationships.h"
#include "serialize.h"
#include "util.h"

/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t * sbomtool_spdx2_package_new(pkgconf_client_t *client, cyclonedx_package_type_t type, const char *name, const char *version, bool additional)
 *
 *    Create Component object (.packages.package)
 *
 *    :param pkgconf_client_t *client: Pkgconf client struct
 *    :param cyclonedx_package_type_t type: Type for this SBOM package
 *    :param const char *name: Name for the package
 *    :param const char *version: Version for the package
 *    :param bool additional: Should licenses and externalReferences to be added
 *    :return: pkgconfcli_serialize_value_t * representing the package object.
 */
pkgconfcli_serialize_value_t *
sbomtool_spdx2_relationship_new(pkgconf_client_t *client, const char *from, const char *to, const char *type)
{
	if (!client || !from || !to || !type)
		return false;

	pkgconfcli_serialize_object_list_t *object_list = pkgconfcli_serialize_object_list_new();
	pkgconfcli_serialize_value_t *ret = NULL;
	char *spdx_ref = NULL;

	if (!object_list)
		goto err;

	if (!(pkgconfcli_serialize_object_add_string(object_list, "relatedSpdxElement", to) &&
		pkgconfcli_serialize_object_add_string(object_list, "spdxElementId", from) &&
		pkgconfcli_serialize_object_add_string(object_list, "relationshipType", type)))
		goto err;

	ret = pkgconfcli_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx2_relationship_new: out of memory");

	free(spdx_ref);
	pkgconfcli_serialize_object_list_free(object_list);
	return ret;
}
