/*
* SPDX-License-Identifier: BSD-2-Clause
*
*​ Copyright (c) 2026 The FreeBSD Foundation
*​
*​ Portions of this software were developed by
* Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
* the FreeBSD Foundation
*/

#include <libpkgconf/config.h>
#include <libpkgconfcli/serialize.h>
#include "spdx2/structure.h"
#include "util.h"


/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx2_structure_new(pkgconf_client_t *client, sbomtool_spdx2_document_t *document, bool is_tool)
 *
 *    Create basic structure of SDPX 3.x document
 *
 *    :param pkgconf_client_t *client: Pkgconf Client
 *    :param sbomtool_spdx2_document_t *document: SPDX document structure which hold needed information
 *    :param bool is_tool: Should tool info be added. True it should and false it shouldn't
 *    :return: pkgconfcli_serialize_value_t * which contains strucre of CycloneDX
 */
pkgconfcli_serialize_value_t *
sbomtool_spdx2_structure_new(pkgconf_client_t *client, const char *document_name, const char *document_license, const char *document_namespace)
{
	pkgconfcli_serialize_object_list_t *root = pkgconfcli_serialize_object_list_new();
	char *spdx_id = NULL;
	pkgconfcli_serialize_value_t *ret = NULL;

	if (!root)
		goto err;

	spdx_id = sbomtool_util_get_sbom_id_int(client, "DOCUMENT");

	if (!spdx_id)
		goto err;

	if (!pkgconfcli_serialize_object_add_string(root, "spdxVersion", SPDX2_SPECVERSION))
		goto err;

	if (!pkgconfcli_serialize_object_add_string(root, "dataLicense", document_license))
		goto err;

	if (!pkgconfcli_serialize_object_add_string(root, "SPDXID", spdx_id))
		goto err;

	free(spdx_id);
	spdx_id = NULL;

	if (!pkgconfcli_serialize_object_add_string(root, "name", document_name))
		goto err;

	if (!pkgconfcli_serialize_object_add_string(root, "documentNamespace", document_namespace))
		goto err;

	if (!pkgconfcli_serialize_object_add_array(root, "externalDocumentRefs", pkgconfcli_serialize_array_new()))
		goto err;

	if (!pkgconfcli_serialize_object_add_array(root, "documentDescribes", pkgconfcli_serialize_array_new()))
		goto err;

	if (!pkgconfcli_serialize_object_add_array(root, "packages", pkgconfcli_serialize_array_new()))
		goto err;

	if (!pkgconfcli_serialize_object_add_array(root, "relationships", pkgconfcli_serialize_array_new()))
		goto err;

	ret = pkgconfcli_serialize_value_object(root);

	root = NULL;

err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx2_structure_new: out of memory");

	pkgconfcli_serialize_object_list_free(root);

	return ret;
}

/*
 * !doc
 *
 * .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx2_structure_new(pkgconf_client_t *client, sbomtool_spdx2_document_t *document, bool is_tool)
 *
 *    Create basic structure of SDPX 3.x document
 *
 *    :param pkgconf_client_t *client: Pkgconf Client
 *    :param sbomtool_spdx2_document_t *document: SPDX document structure which hold needed information
 *    :param bool is_tool: Should tool info be added. True it should and false it shouldn't
 *    :return: pkgconfcli_serialize_value_t * which contains strucre of CycloneDX
 */
bool
sbomtool_spdx2_structure_creation_info(pkgconf_client_t *client, pkgconfcli_serialize_value_t *spdx_doc, const char *timestamp, const char *manufacturer_name, const char *manufacturer_url, bool add_tool)
{
	pkgconfcli_serialize_object_list_t *object_list = pkgconfcli_serialize_object_list_new();
	pkgconfcli_serialize_array_t *creators = NULL;
	pkgconfcli_serialize_value_t *ret = NULL;
	char *creator = NULL;

	(void)manufacturer_url;
	(void)add_tool;
	(void)client;

	if (!object_list)
		goto err;

	if (!pkgconfcli_serialize_object_add_string(object_list, "created", timestamp))
		goto err;

	creators = pkgconfcli_serialize_array_new();

	if (!creators)
		goto err;

	creator = sbomtool_spdx2_structure_creator(client, "Person", manufacturer_name);

	if (!creator)
		goto err;

	if (!pkgconfcli_serialize_array_add_string(creators, creator))
		goto err;

	if (add_tool)
	{
		free(creator);
		creator = NULL;

		creator = sbomtool_spdx2_structure_creator(client, "Tool", "sbomtool");

		if (!creator)
			goto err;

		if (!pkgconfcli_serialize_array_add_string(creators, creator))
			goto err;
	}


	if (!pkgconfcli_serialize_object_add_array(object_list, "creators", creators))
	{
		creators = NULL;
		goto err;
	}

	creators = NULL;

	if (!pkgconfcli_serialize_object_add_object(pkgconfcli_serialize_value_get_object(spdx_doc), "creationInfo", object_list))
	{
		object_list = NULL;
		goto err;
	}

	return true;
err:
	if (!ret)
		pkgconf_error(client, "sbomtool_spdx2_structure_creation_info: out of memory");

	free(creator);
	pkgconfcli_serialize_object_list_free(object_list);
	pkgconfcli_serialize_array_free(creators);
	return false;
}

char *
sbomtool_spdx2_structure_creator(pkgconf_client_t *client, const char *type, const char *creator)
{
	pkgconf_buffer_t maintainer_buf = PKGCONF_BUFFER_INITIALIZER;
	char *rtn = NULL;

	(void)client;

	if (!type || !creator)
		return NULL;

	if (!(pkgconf_buffer_append(&maintainer_buf, type) &&
		pkgconf_buffer_append(&maintainer_buf, ": ") &&
		pkgconf_buffer_append(&maintainer_buf, creator)))
	{
		pkgconf_buffer_finalize(&maintainer_buf);
		return NULL;
	}

	rtn = strdup(pkgconf_buffer_str_or_empty(&maintainer_buf));
	pkgconf_buffer_finalize(&maintainer_buf);

	return rtn;
}

