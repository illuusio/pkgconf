/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2025 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include <stdlib.h>
#include <string.h>
#include <libpkgconf/libpkgconf.h>
#include <libpkgconfcli/serialize.h>
#include "spdx3/simplelicensing.h"
#include "spdx3/software.h"
#include "spdx3/core.h"
#include "util.h"

static bool
serialize_copyright_lines_to_object(pkgconfcli_serialize_object_list_t *object_list, const pkgconf_list_t *copyright_lines)
{
	pkgconf_buffer_t copyright_buf = PKGCONF_BUFFER_INITIALIZER;
	const pkgconf_node_t *node;

	if (copyright_lines->head == NULL)
		return pkgconfcli_serialize_object_add_string(object_list, "software_copyrightText", "NOASSERTION") != NULL;

	PKGCONF_FOREACH_LIST_ENTRY(copyright_lines->head, node)
	{
		const pkgconf_bufferset_t *set = node->data;
		if (!pkgconf_buffer_join(&copyright_buf, '\n', pkgconf_buffer_str_or_empty(&set->buffer), NULL))
		{
			pkgconf_buffer_finalize(&copyright_buf);
			return false;
		}
	}

	bool ok = pkgconfcli_serialize_object_add_string(object_list, "software_copyrightText", pkgconf_buffer_str_or_empty(&copyright_buf)) != NULL;
	pkgconf_buffer_finalize(&copyright_buf);
	return ok;
}

static const char *
software_get_string(pkgconfcli_serialize_value_t *value, const char *key)
{
	pkgconfcli_serialize_value_t *element = pkgconfcli_serialize_value_object_find(value, key);

	if (!element)
		return NULL;

	if (pkgconfcli_serialize_is_value(element, PKGCONFCLI_SERIALIZE_TYPE_STRING))
	{
		return pkgconfcli_serialize_value_get_string(element);
	}

	return NULL;
}
static char *
software_add_license(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, const char *expression)
{
	pkgconf_node_t *node = NULL;
	const char *cmp_expression = 0;
	char *spdx_id = NULL;
	bool found = false;

	PKGCONF_FOREACH_LIST_ENTRY(document->licenses->items.head, node)
	{
		pkgconfcli_serialize_value_t *item = node->data;
		if (pkgconfcli_serialize_is_value(item, PKGCONFCLI_SERIALIZE_TYPE_OBJECT))
		{
			cmp_expression = software_get_string(item, "simplelicensing_licenseExpression");

			if (!cmp_expression)
			{
				break;
			}

			if (!strcmp(expression, cmp_expression))
			{
				found = true;
				break;
			}
		}
	}

	pkgconfcli_serialize_value_t *license_obj = sbomtool_spdx3_simplelicensing_licenseExpression(client, document, expression);

	if (license_obj)
	{
		spdx_id = strdup (software_get_string(license_obj, "spdxId"));

		if (!found)
		{
			if (!pkgconfcli_serialize_array_add_take(document->licenses, license_obj))
			{
				free(spdx_id);
				spdx_id = NULL;
			}
		}
		else
		{
			pkgconfcli_serialize_value_free(license_obj);
		}
	}

	return spdx_id;
}

/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx3_software_sbom_to_object(pkgconf_client_t *client, spdxtool_software_sbom_t *sbom)
 *
 *    Serialize /Software/Sbom struct to a JSON value tree. As a side effect,
 *    the package associated with the SBOM's rootElement is registered on the
 *    document via sbomtool_spdx3_core_spdx_document_add_package, and relationship
 *    element IDs are registered via sbomtool_spdx3_core_spdx_document_add_element.
 *
 *    :param pkgconf_client_t *client: The pkgconf client being accessed.
 *    :param sbomtool_spdx3_software_sbom_t *sbom: Sbom struct to be serialized.
 *    :return: pkgconfcli_serialize_value_t * representing the Sbom object.
 */
pkgconfcli_serialize_value_t *
sbomtool_spdx3_software_sbom(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, const char *name)
{
	pkgconfcli_serialize_value_t *ret = NULL;
	pkgconfcli_serialize_object_list_t *object_list = NULL;
	pkgconfcli_serialize_array_t *sbom_type_array = NULL;
	pkgconfcli_serialize_array_t *root_element_array = NULL;
	pkgconfcli_serialize_array_t *element_array = NULL;
	char *spdx_id = NULL;
	// char sep = sbomtool_spdx3_util_get_uri_separator(client);

	//spdx_id = sbomtool_spdx3_util_tuple_lookup(client, &sbom->rootElement->vars, "spdxId");
	//if (!spdx_id)
	//	goto err;

	spdx_id = sbomtool_util_get_sbom_id_string(client, "software_Sbom", name);
	if (!spdx_id)
		goto err;

	object_list = pkgconfcli_serialize_object_list_new();
	if (!object_list)
		goto err;

	sbom_type_array = pkgconfcli_serialize_array_new();
	if (!sbom_type_array)
		goto err;

	if (!pkgconfcli_serialize_array_add_string(sbom_type_array, "build"))
		goto err;

	root_element_array = pkgconfcli_serialize_array_new();
	if (!root_element_array)
		goto err;

	//if (!pkgconfcli_serialize_array_add_string(root_element_array, "kukkel"))
	//	goto err;

	element_array = pkgconfcli_serialize_array_new();

	if (!element_array)
		goto err;

	if (!(pkgconfcli_serialize_object_add_string(object_list, "type", "software_Sbom") &&
		pkgconfcli_serialize_object_add_string(object_list, "creationInfo", document->creation_info_id) &&
		pkgconfcli_serialize_object_add_string(object_list, "spdxId", spdx_id)))
	{
		goto err;
	}

	/* object_add_array always takes ownership of the array (it is freed even on
	 * failure), so clear our reference before checking the result to avoid a
	 * double free at the error label.
	 */
	bool ok = pkgconfcli_serialize_object_add_array(object_list, "software_sbomType", sbom_type_array);
	sbom_type_array = NULL;
	if (!ok)
		goto err;

	ok = pkgconfcli_serialize_object_add_array(object_list, "rootElement", root_element_array);
	root_element_array = NULL;
	if (!ok)
		goto err;

	ok = pkgconfcli_serialize_object_add_array(object_list, "element", element_array);
	element_array = NULL;
	if (!ok)
		goto err;

	ret = pkgconfcli_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx3_software_sbom_to_object: out of memory");

	free(spdx_id);
	pkgconfcli_serialize_object_list_free(object_list);
	pkgconfcli_serialize_array_free(sbom_type_array);
	pkgconfcli_serialize_array_free(root_element_array);
	pkgconfcli_serialize_array_free(element_array);
	return ret;
}

/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx3_software_package_to_object(pkgconf_client_t *client, pkgconf_pkg_t *pkg, spdxtool_core_spdx_document_t *spdx)
 *
 *    Serialize /Software/Package struct to a JSON value tree. As a side effect,
 *    any license and dependency relationships generated during serialization are
 *    added to the document via sbomtool_spdx3_core_spdx_document_add_relationship.
 *
 *    :param pkgconf_client_t *client: The pkgconf client being accessed.
 *    :param pkgconf_pkg_t *pkg: Package struct to be serialized.
 *    :param sbomtool_spdx3_core_spdx_document_t *spdx: SpdxDocument to which generated relationships are added.
 *    :pkgconfcli_serialize_value_t *sbom: SBOM object which relates to this package
 *    :return: pkgconfcli_serialize_value_t * representing the Package object.
 */
pkgconfcli_serialize_value_t *
sbomtool_spdx3_software_package(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, pkgconf_pkg_t *pkg, pkgconfcli_serialize_value_t *sbom)
{
	char *spdx_id = NULL;
	char *license_spdx_id = NULL;
	const char *relation_spdx_id = NULL;
	pkgconfcli_serialize_value_t *ret = NULL;
	// pkgconfcli_serialize_value_t *relationship_value = NULL;
	pkgconfcli_serialize_object_list_t *object_list = NULL;
	pkgconfcli_serialize_array_t *originated_by = NULL;
	pkgconfcli_serialize_array_t *has_declared_license = NULL;
	pkgconfcli_serialize_array_t *has_concluded_license = NULL;
	pkgconfcli_serialize_array_t *depend_on_array = NULL;
	pkgconfcli_serialize_value_t *sbom_root_element = NULL;
	pkgconfcli_serialize_value_t *sbom_common_element = NULL;
	pkgconfcli_serialize_value_t *spdx_element = NULL;
	pkgconfcli_serialize_value_t *depencency_element = NULL;
	pkgconf_node_t *node = NULL;
	bool add_array = false;

	sbom_root_element = pkgconfcli_serialize_value_object_find(sbom, "rootElement");

	if (!sbom_root_element)
		goto err;

	sbom_common_element = pkgconfcli_serialize_value_object_find(sbom, "element");

	if (!sbom_common_element)
		goto err;

	spdx_id = sbomtool_util_get_sbom_id_string(client, "Package", pkg->id);
	if (!spdx_id)
		goto err;

	if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_root_element), pkgconfcli_serialize_value_string(spdx_id)))
		goto err;

	object_list = pkgconfcli_serialize_object_list_new();
	if (!object_list)
		goto err;

	originated_by = pkgconfcli_serialize_array_new();
	if (!originated_by)
		goto err;

	if (!pkgconfcli_serialize_array_add_string(originated_by, document->agent_spdx_id))
		goto err;

	if (!(pkgconfcli_serialize_object_add_string(object_list, "type", "software_Package") &&
		pkgconfcli_serialize_object_add_string(object_list, "creationInfo", document->creation_info_id) &&
		pkgconfcli_serialize_object_add_string(object_list, "spdxId", spdx_id) &&
		pkgconfcli_serialize_object_add_string(object_list, "name", pkg->realname)))
	{
		goto err;
	}

	bool ok = pkgconfcli_serialize_object_add_array(object_list, "originatedBy", originated_by);
	originated_by = NULL;
	if (!ok)
		goto err;

	// supplier = sbomtool_spdx3_util_tuple_lookup(client, &pkg->vars, "suppliedBy");
	//if (supplier && !pkgconfcli_serialize_object_add_string(object_list, "suppliedBy", "Muumi"))
	//	goto err;

	if (!serialize_copyright_lines_to_object(object_list, &pkg->copyright))
		goto err;

	if (!pkgconfcli_serialize_object_add_string(object_list, "software_homePage",
		pkg->url ? pkg->url : ""))
	{
		goto err;
	}

	if (!pkgconfcli_serialize_object_add_string(object_list, "software_downloadLocation",
		pkg->source ? pkg->source : ""))
	{
		goto err;
	}

	if (!pkgconfcli_serialize_object_add_string(object_list, "software_packageVersion", pkg->version))
		goto err;

	has_declared_license = pkgconfcli_serialize_array_new();

	if (!has_declared_license)
		goto err;

	has_concluded_license = pkgconfcli_serialize_array_new();

	if (!has_concluded_license)
	{
		pkgconfcli_serialize_array_free(has_declared_license);
		goto err;
	}

	PKGCONF_FOREACH_LIST_ENTRY(pkg->license.head, node)
	{
		const pkgconf_license_t *license = node->data;
		if (license->type == PKGCONF_LICENSE_EXPRESSION)
		{

			license_spdx_id = software_add_license(client, document, license->data);

			if (!license_spdx_id)
				goto err;

			pkgconfcli_serialize_array_add_string(has_declared_license, license_spdx_id);
			pkgconfcli_serialize_array_add_string(has_concluded_license, license_spdx_id);


			if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(license_spdx_id)))
			{
				pkgconfcli_serialize_array_free(has_declared_license);
				pkgconfcli_serialize_array_free(has_concluded_license);
				goto err;
			}

			free(license_spdx_id);
		}
	}

	depencency_element = sbomtool_core_relationship(client, document, spdx_id, has_declared_license, pkg->id, "hasDeclaredLicense", NULL);

	if (!depencency_element)
		goto err;

	relation_spdx_id = software_get_string(depencency_element, "spdxId");

	if (!relation_spdx_id)
		goto err;

	if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(relation_spdx_id)))
		goto err;

	if(!pkgconfcli_serialize_array_add_take(document->relationships, depencency_element))
		goto err;

	depencency_element = sbomtool_core_relationship(client, document, spdx_id, has_concluded_license, pkg->id, "hasConcludedLicense", NULL);

	if (!depencency_element)
		goto err;

	relation_spdx_id = software_get_string(depencency_element, "spdxId");

	if (!relation_spdx_id)
		goto err;

	if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(relation_spdx_id)))
		goto err;

	if(!pkgconfcli_serialize_array_add_take(document->relationships, depencency_element))
		goto err;

	depend_on_array = pkgconfcli_serialize_array_new();

	PKGCONF_FOREACH_LIST_ENTRY(pkg->required.head, node)
	{
		pkgconf_dependency_t *dep = node->data;
		pkgconf_pkg_t *match = dep->match;

		add_array = true;

		if (match == NULL)
			continue;

		char *spdx_id_relation = sbomtool_util_get_sbom_id_string(client, "Package", match->id);

		if (!spdx_id_relation)
			goto err;

		if(!pkgconfcli_serialize_array_add_string(depend_on_array, spdx_id_relation))
		{
			free(spdx_id_relation);
			goto err;
		}

		free(spdx_id_relation);
	}

	if (add_array)
	{
		depencency_element = sbomtool_core_relationship(client, document, spdx_id, depend_on_array, pkg->id, "dependsOn", NULL);

		if (!depencency_element)
			goto err;

		spdx_element = pkgconfcli_serialize_value_object_find(depencency_element, "spdxId");

		if (!spdx_element)
			goto err;

		relation_spdx_id = pkgconfcli_serialize_value_get_string(spdx_element);

		if (!relation_spdx_id)
			goto err;

		if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(relation_spdx_id)))
			goto err;

		if(!pkgconfcli_serialize_array_add_take(document->relationships, depencency_element))
			goto err;
	}
	else
		pkgconfcli_serialize_array_free(depend_on_array);

	depend_on_array = pkgconfcli_serialize_array_new();
	add_array = false;

	PKGCONF_FOREACH_LIST_ENTRY(pkg->requires_private.head, node)
	{
		pkgconf_dependency_t *dep = node->data;
		pkgconf_pkg_t *match = dep->match;

		add_array = true;

		if (match == NULL)
			continue;

		char *spdx_id_relation = sbomtool_util_get_sbom_id_string(client, "Package", match->id);

		if (!spdx_id_relation)
			goto err;

		if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(spdx_id_relation)))
			goto err;

		if(!pkgconfcli_serialize_array_add_string(depend_on_array, spdx_id_relation))
		{
			free(spdx_id_relation);
			goto err;
		}

		free(spdx_id_relation);

	}

	if (add_array)
	{
		depencency_element =  sbomtool_core_relationship(client, document, spdx_id, depend_on_array, pkg->id, "dependsOn", "development");

		if (!depencency_element)
			goto err;

		spdx_element = pkgconfcli_serialize_value_object_find(depencency_element, "spdxId");

		if (!spdx_element)
			goto err;

		relation_spdx_id = pkgconfcli_serialize_value_get_string(spdx_element);

		if (!relation_spdx_id)
			goto err;

		if(!pkgconfcli_serialize_array_add_take(pkgconfcli_serialize_value_get_array(sbom_common_element), pkgconfcli_serialize_value_string(relation_spdx_id)))
			goto err;

		if(!pkgconfcli_serialize_array_add_take(document->relationships, depencency_element))
			goto err;
	}
	else
		pkgconfcli_serialize_array_free(depend_on_array);

	ret = pkgconfcli_serialize_value_object(object_list);
	object_list = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx3_software_package_to_object: out of memory");

	//free(creation_info);
	// free(relation_spdx_id);
	free(spdx_id);
	//free(agent);
	//free(supplier);
	//free(spdx_id_license);
	// pkgconf_license_free(&relations);
	/*if (cpy_relations != NULL)
	{
		pkgconf_license_free(cpy_relations);
		free(cpy_relations);
	}*/
	pkgconfcli_serialize_object_list_free(object_list);
	pkgconfcli_serialize_array_free(originated_by);
	return ret;
}

/*
 * !doc
 *
 * .. c:function:: void sbomtool_cyclondex_component_add_package(pkgconf_client_t *client, pkgconf_pkg_t *pkg, void *ptr, unsigned int iter_flags)
 *
 *    This should be passes to package traverse function as callback. Adds components to CyclonDX SBOM
 *
 *    :param pkgconf_client_t *client: Pkgconf client struct
 *    :param  pkgconf_pkg_t *pkg: Package struct
 *    :param void *ptr: This should be CycloneDX struct
 *    :param onst char *iter_flags: Flags which are passed to function
 */
void
sbomtool_spdx3_software_add_package(pkgconf_client_t *client, pkgconf_pkg_t *pkg, void *ptr, unsigned int iter_flags)
{
	(void) iter_flags;

	//pkgconf_node_t *iter = NULL;
	sbomtool_spdx3_document_t *document = (sbomtool_spdx3_document_t *) ptr;
	pkgconfcli_serialize_value_t *sbom_obj = NULL;
	// pkgconfcli_serialize_value_t *package_obj = NULL;
	// char *sbom_spdx_id_string = NULL;

	/*generate_spdx_ctx_t *ctx = ptr;
	spdxtool_core_spdx_document_t *document = ctx->document;
	pkgconf_node_t *iter = NULL;
	spdxtool_software_sbom_t *sbom = NULL;
	char *package_spdx = NULL;
	char *spdx_id_string = NULL;
	pkgconf_buffer_t spdx_id_buf = PKGCONF_BUFFER_INITIALIZER;
	pkgconf_buffer_t concluded_buf = PKGCONF_BUFFER_INITIALIZER;
	char sep = spdxtool_util_get_uri_separator(client);*/

	if (pkg->flags & PKGCONF_PKG_PROPF_VIRTUAL)
		return;

	sbom_obj = sbomtool_spdx3_software_sbom(client, document, pkg->id);

	if (!sbom_obj)
		goto err;

	pkgconfcli_serialize_array_add_take(document->graph, sbom_obj);

	pkgconfcli_serialize_array_add_take(document->graph, sbomtool_spdx3_software_package(client, document, pkg, sbom_obj));


	/*sbom = spdxtool_software_sbom(client, document);
	free(spdx_id_string);
	spdx_id_string = NULL;
	if (!sbom)
		goto err;

	sbom->spdx_document = document;
	sbom->rootElement = pkg;

	package_spdx = spdxtool_util_get_spdx_id_string(client, "Package", pkg->id);
	if (!package_spdx)
		goto err;

	if (pkgconf_tuple_add(client, &pkg->vars, "spdxId", package_spdx, false, 0) == NULL)
		goto err;
	free(package_spdx);
	package_spdx = NULL;

	if (pkgconf_tuple_add(client, &pkg->vars, "creationInfo", document->creation_info, false, 0) == NULL ||
		pkgconf_tuple_add(client, &pkg->vars, "agent", document->agent, false, 0) == NULL)
	{
		goto err;
	}

	if (pkg->maintainer != NULL)
	{
		const char *supplier = spdxtool_core_spdx_document_add_maintainer(client, document, pkg->maintainer);
		if (!supplier)
			goto err;

		if (pkgconf_tuple_add(client, &pkg->vars, "suppliedBy", supplier, false, 0) == NULL)
			goto err;
	}

	if (pkg->license.head != NULL)
	{
		if (!pkgconf_buffer_append_fmt(&spdx_id_buf, "%s%chasDeclaredLicense", pkg->id, sep))
			goto err;

		char *spdx_id_name = pkgconf_buffer_freeze(&spdx_id_buf);
		if (!spdx_id_name)
			goto err;

		package_spdx = spdxtool_util_get_spdx_id_string(client, "Relationship", spdx_id_name);
		free(spdx_id_name);
		if (!package_spdx)
			goto err;

		if (pkgconf_tuple_add(client, &pkg->vars, "hasDeclaredLicense", package_spdx, false, 0) == NULL)
			goto err;
		free(package_spdx);
		package_spdx = NULL;

		if (!pkgconf_buffer_append_fmt(&concluded_buf, "%s%chasConcludedLicense", pkg->id, sep))
			goto err;

		spdx_id_name = pkgconf_buffer_freeze(&concluded_buf);
		if (!spdx_id_name)
			goto err;

		package_spdx = spdxtool_util_get_spdx_id_string(client, "Relationship", spdx_id_name);
		free(spdx_id_name);
		if (!package_spdx)
			goto err;

		if (pkgconf_tuple_add(client, &pkg->vars, "hasConcludedLicense", package_spdx, false, 0) == NULL)
			goto err;
		free(package_spdx);
		package_spdx = NULL;

		PKGCONF_FOREACH_LIST_ENTRY(pkg->license.head, iter)
		{
			const pkgconf_license_t *license = iter->data;
			if (license->type == PKGCONF_LICENSE_EXPRESSION)
			{
				if (!spdxtool_core_spdx_document_add_license(client, document, license->data))
					goto err;
			}
		}
	}

	if (!generate_spdx_document_add_sbom(client, document, sbom))
		goto err;

	sbom = NULL;*/
	return;

	err:
	pkgconfcli_serialize_value_free(sbom_obj);
	//ctx->failed = true;
	//pkgconf_error(client, "generate_spdx_package: failed for %s", pkg->id);
	//free(package_spdx);
	//free(spdx_id_string);
	//pkgconf_buffer_finalize(&spdx_id_buf);
	//pkgconf_buffer_finalize(&concluded_buf);
	//spdxtool_software_sbom_free(sbom);

}
