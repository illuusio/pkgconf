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
#include "spdx2/packages.h"
#include "spdx2/relationships.h"
#include "serialize.h"
#include "util.h"

static bool
package_copyright_lines_to_object(pkgconfcli_serialize_object_list_t *object_list, const pkgconf_list_t *copyright_lines)
{
	pkgconf_buffer_t copyright_buf = PKGCONF_BUFFER_INITIALIZER;
	const pkgconf_node_t *node;

	if (copyright_lines->head == NULL)
		return true;

	PKGCONF_FOREACH_LIST_ENTRY(copyright_lines->head, node)
	{
		const pkgconf_bufferset_t *set = node->data;
		if (!pkgconf_buffer_join(&copyright_buf, '\n', pkgconf_buffer_str_or_empty(&set->buffer), NULL))
		{
			pkgconf_buffer_finalize(&copyright_buf);
			return false;
		}
	}

	bool ok = pkgconfcli_serialize_object_add_string(object_list, "copyrightText", pkgconf_buffer_str_or_empty(&copyright_buf)) != NULL;
	pkgconf_buffer_finalize(&copyright_buf);
	return ok;
}

static bool
package_maintainer_info(pkgconfcli_serialize_object_list_t *object_list, const char *type, const char *maintainer)
{
	pkgconf_buffer_t maintainer_buf = PKGCONF_BUFFER_INITIALIZER;

	if (!type || !maintainer)
		return true;

	if (!(pkgconf_buffer_append(&maintainer_buf, type) &&
	        pkgconf_buffer_append(&maintainer_buf, ": ") &&
	        pkgconf_buffer_append(&maintainer_buf, maintainer)))
	{
		pkgconf_buffer_finalize(&maintainer_buf);
		return false;
	}

	bool ok = pkgconfcli_serialize_object_add_string(object_list, "supplier", pkgconf_buffer_str_or_empty(&maintainer_buf)) != NULL;
	pkgconf_buffer_finalize(&maintainer_buf);
	return ok;
}

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
sbomtool_spdx2_package_new(pkgconf_client_t *client, const char *name, const char *version)
{
	if (!client || !name || !version)
		return false;

	pkgconfcli_serialize_object_list_t *object_list = pkgconfcli_serialize_object_list_new();
	pkgconfcli_serialize_value_t *ret = NULL;
	char *spdx_ref = NULL;

	if (!object_list)
		goto err;

	spdx_ref = sbomtool_util_get_sbom_id_string(client, "Package", name);
	if (!spdx_ref)
		goto err;

	if (!pkgconfcli_serialize_object_add_string(object_list, "SPDXID", spdx_ref))
		goto err;

	if (!(pkgconfcli_serialize_object_add_string(object_list, "name", name) &&
	        pkgconfcli_serialize_object_add_string(object_list, "versionInfo", version)))
		goto err;

	if (!pkgconfcli_serialize_object_add_bool(object_list, "filesAnalyzed", false))
		goto err;

	ret = pkgconfcli_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx2_package_new: out of memory");

	free(spdx_ref);
	pkgconfcli_serialize_object_list_free(object_list);
	return ret;
}

/*
 * !doc
 *
 * .. c:function:: void sbomtool_spdx2_package_add_package(pkgconf_client_t *client, pkgconf_pkg_t *pkg, void *ptr, unsigned int iter_flags)
 *
 *    This should be passed to package traverse function as callback.
 *
 *    :param pkgconf_client_t *client: Pkgconf client struct
 *    :param  pkgconf_pkg_t *pkg: Package struct
 *    :param void *ptr: This should be CycloneDX struct
 *    :param onst char *iter_flags: Flags which are passed to function
 */
void
sbomtool_spdx2_package_add_package(pkgconf_client_t *client, pkgconf_pkg_t *pkg, void *ptr, unsigned int iter_flags)
{
	(void) iter_flags;
	const pkgconf_node_t *iter = NULL;
	char *dep_id = NULL;

	if (!ptr)
		return;

	if (pkg->flags & PKGCONF_PKG_PROPF_VIRTUAL)
		return;

	pkgconfcli_serialize_value_t *spdx_doc = (pkgconfcli_serialize_value_t *) ptr;
	pkgconfcli_serialize_value_t *packages = pkgconfcli_serialize_value_object_find(spdx_doc, "packages");
	pkgconfcli_serialize_value_t *relationships = pkgconfcli_serialize_value_object_find(spdx_doc, "relationships");
	pkgconfcli_serialize_value_t *documentDescribes = pkgconfcli_serialize_value_object_find(spdx_doc, "documentDescribes");
	pkgconfcli_serialize_value_t *package = NULL;
	pkgconfcli_serialize_value_t *package_spdx_id = NULL;
	pkgconfcli_serialize_value_t *relationship_obj = NULL;

	if (!packages || !relationships || !documentDescribes)
		goto err;

	package = sbomtool_spdx2_package_new(client, pkg->id, pkg->version);

	if (!package)
		goto err;

	package_spdx_id = pkgconfcli_serialize_value_object_find(package, "SPDXID");

	if (!package_spdx_id)
		goto err;

	pkgconfcli_serialize_array_add_string(pkgconfcli_serialize_value_get_array(documentDescribes), pkgconfcli_serialize_value_get_string(package_spdx_id));

	if (!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(packages), package))
		goto err;

	if (pkg->license.head)
	{
		pkgconf_buffer_t license_buf = PKGCONF_BUFFER_INITIALIZER;

		if (!pkgconf_license_render(client, &pkg->license, &license_buf))
			goto err;

		const char *license_str = pkgconf_buffer_str_or_empty(&license_buf);

		if (!license_str)
		{
			pkgconf_buffer_finalize(&license_buf);
			goto err;
		}

		if (!(pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "licenseConcluded", license_str) &&
		        pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "licenseDeclared", license_str)))
		{
			pkgconf_buffer_finalize(&license_buf);
			goto err;
		}

	}
	else
	{
		if (!(pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "licenseConcluded", "NOASSERTION") &&
		        pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "licenseDeclared", "NOASSERTION")))
			goto err;
	}

	if (!package_copyright_lines_to_object(pkgconfcli_serialize_value_get_object(package), &pkg->copyright))
		goto err;

	if (pkg->maintainer)
	{
		if (!package_maintainer_info(pkgconfcli_serialize_value_get_object(package), "Person", pkg->maintainer))
			goto err;
	}

	if (pkg->url)
		if (!pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "homepage", pkg->url))
			goto err;

	if (pkg->source)
		if (!pkgconfcli_serialize_object_add_string(pkgconfcli_serialize_value_get_object(package), "downloadLocation", pkg->source))
			goto err;

	PKGCONF_FOREACH_LIST_ENTRY(pkg->required.head, iter)
	{
		pkgconf_dependency_t *dep = iter->data;
		pkgconf_pkg_t *match = dep->match;
		dep_id = sbomtool_util_get_sbom_id_string(client, "Package", match->id);

		if (!dep_id)
			goto err;

		relationship_obj = sbomtool_spdx2_relationship_new(client, pkgconfcli_serialize_value_get_string(package_spdx_id), dep_id, "DEPENDS_ON");

		if (!relationship_obj)
			goto err;

		if (!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(relationships), relationship_obj))
			goto err;

		free(dep_id);
		dep_id = NULL;
		relationship_obj = NULL;
	}

	PKGCONF_FOREACH_LIST_ENTRY(pkg->requires_private.head, iter)
	{
		pkgconf_dependency_t *dep = iter->data;
		pkgconf_pkg_t *match = dep->match;
		dep_id = sbomtool_util_get_sbom_id_string(client, "Package", match->id);

		if (!dep_id)
			goto err;

		relationship_obj = sbomtool_spdx2_relationship_new(client, pkgconfcli_serialize_value_get_string(package_spdx_id), dep_id, "DEPENDS_ON");

		if (!relationship_obj)
			goto err;

		if (!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(relationships), relationship_obj))
			goto err;

		free(dep_id);
		dep_id = NULL;
		relationship_obj = NULL;
	}

	return;

err:
	pkgconfcli_serialize_value_free(package);
	pkgconfcli_serialize_value_free(relationship_obj);
	free(dep_id);
}
