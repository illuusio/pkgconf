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
#include "spdx3/structure.h"
#include "spdx3/core.h"

/*
* !doc
*
* .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx3_structure_new(pkgconf_client_t *client, int numversion)
*
*    Create basic structure of CycloneDX document
*
*    :param pkgconf_client_t *client: Pkgconf Client
*    :param int numversion: Current revision of document
*    :return: pkgconfcli_serialize_value_t * which contains strucre of CycloneDX
*/
pkgconfcli_serialize_value_t *
sbomtool_spdx3_structure_new(pkgconf_client_t *client, sbomtool_spdx3_document_t *document, bool is_tool)
{
	pkgconfcli_serialize_object_list_t *object_list = pkgconfcli_serialize_object_list_new();
	pkgconfcli_serialize_value_t *agent = NULL;
	pkgconfcli_serialize_value_t *tool = NULL;
	pkgconfcli_serialize_value_t *agent_value = NULL;
	pkgconfcli_serialize_value_t *tool_value = NULL;
	const char *tool_spdx_id = NULL;
	// pkgconfcli_serialize_value_t *ret = NULL;
	//pkgconfcli_serialize_array_t *graph = NULL;

	if (!object_list)
	{
		goto err;
	}

	if (!pkgconfcli_serialize_object_add_string(object_list, "@context", SPDX3_CONTEXT))
		goto err;

	document->graph = pkgconfcli_serialize_array_new();

	if (!document->graph)
		goto err;

	if (!pkgconfcli_serialize_object_add_array(object_list, "@graph", document->graph))
		goto err;

	agent = sbomtool_spdx3_core_agent(client, document->creation_info_id, document->agent_name);

	if (!pkgconfcli_serialize_array_add_take(document->graph, agent))
		goto err;

	agent_value = pkgconfcli_serialize_value_object_find(agent, "spdxId");

	if (!agent_value || !pkgconfcli_serialize_is_value(agent_value, PKGCONFCLI_SERIALIZE_TYPE_STRING))
		goto err;


	if (is_tool)
	{
		tool = sbomtool_spdx3_core_tool(client, document->creation_info_id, PACKAGE_NAME, "sbomtool");

		if (!pkgconfcli_serialize_array_add_take(document->graph, tool))
			goto err;

		tool_value = pkgconfcli_serialize_value_object_find(tool, "spdxId");

		if (!tool_value || !pkgconfcli_serialize_is_value(tool_value, PKGCONFCLI_SERIALIZE_TYPE_STRING))
			goto err;

		tool_spdx_id = pkgconfcli_serialize_value_get_string(tool_value);
	}

	if (!pkgconfcli_serialize_array_add_take(document->graph,
											sbomtool_spdx3_core_creation_info(client,
											pkgconfcli_serialize_value_get_string(agent_value),
											tool_spdx_id,
											document->creation_info_id,
											document->timestamp)))
		goto err;

	document->agent_spdx_id = pkgconfcli_serialize_value_get_string(agent_value);
	document->document_root = pkgconfcli_serialize_value_object(object_list);

	if (!document->document_root)
	{
		goto err;
	}

	object_list = NULL;

	err:
	if (!document->document_root)
		pkgconf_error(client, "sbomtool_spdx3_structure_new: out of memory");

	pkgconfcli_serialize_object_list_free(object_list);
	return document->document_root;
}

/*
* !doc
*
* .. c:function:: pkgconfcli_serialize_value_t *sbomtool_spdx3_structure_add_metadata(pkgconf_client_t *client, pkgconfcli_serialize_value_t *cyclonedx_doc, const char *timestamp, const char *manufacturer_name, const char *manufacturer_url, bool add_tool)
*
*
*    Create Metadata part to CycloneDX doc
*
*    :param pkgconf_client_t *client: Pkgconf Client struct
*    :param pkgconfcli_serialize_value_t *cyclonedx_doc: Current revision of document
*    :param const char *timestamp: Timestamp to be used or NULL if current is wanted
*    :param const char *manufacturer_name: Manufacturer name
*    :param const char *manufacturer_url: Manufacturer URL
*    :param bool add_tool: Should tool info be added (if true it will be added to document)
*    :return: pkgconfcli_serialize_value_t * which contains strucre of CycloneDX
*/
/*pkgconfcli_serialize_value_t *
sbomtool_spdx3_structure_add_metadata(pkgconf_client_t *client, pkgconfcli_serialize_value_t *cyclonedx_doc, const char *timestamp, const char *manufacturer_name, const char *manufacturer_url, bool add_tool)
{
	pkgconfcli_serialize_value_t *metadata = pkgconfcli_serialize_value_object_find(cyclonedx_doc, "metadata");
	pkgconfcli_serialize_object_list_t *object_list = NULL;

	if (!metadata || !manufacturer_name || !manufacturer_url || !pkgconfcli_serialize_is_value(metadata, PKGCONFCLI_SERIALIZE_TYPE_OBJECT))
		return NULL;

	object_list = pkgconfcli_serialize_get_value_object(metadata);

	if (!object_list)
		return NULL;

	sbomtool_spdx3_metadata_add_timestamp(client, object_list, timestamp);
	sbomtool_spdx3_metadata_add_manufacturer(client, object_list, manufacturer_name, manufacturer_url);

	if (add_tool)
		sbomtool_spdx3_metadata_add_tools(client, object_list);

	return metadata;
}*/
