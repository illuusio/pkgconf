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
#include "libpkgconf/libpkgconf.h"
#include "spdx2/spdx.h"
#include "serialize.h"


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
sbomtool_spdx2_spdx_value_to_buf(pkgconf_buffer_t *buffer, pkgconfcli_serialize_value_t *value)
{
	pkgconfcli_serialize_array_t *root_array = NULL;
	// pkgconfcli_serialize_array_t *obj_array = NULL;
	pkgconfcli_serialize_object_list_t *object_list = NULL;
	pkgconf_node_t *root_iter = NULL;
	pkgconf_node_t *obj_iter = NULL;

	if (!value || !buffer)
		goto err;

	if (!pkgconfcli_serialize_is_value(value, PKGCONFCLI_SERIALIZE_TYPE_ARRAY))
		goto err;

	root_array = pkgconfcli_serialize_value_get_array(value);

	PKGCONF_FOREACH_LIST_ENTRY(root_array->items.head, root_iter)
	{
		pkgconfcli_serialize_value_t *entry = root_iter->data;

		if (!pkgconfcli_serialize_is_value(entry, PKGCONFCLI_SERIALIZE_TYPE_OBJECT))
			goto err;

		object_list = pkgconfcli_serialize_value_get_object(entry);

		PKGCONF_FOREACH_LIST_ENTRY(object_list->entries.head, obj_iter)
		{
			pkgconfcli_serialize_object_t *obj_entry = obj_iter->data;

			if (!obj_entry || !obj_entry->key)
				continue;

			pkgconf_buffer_append(buffer, obj_entry->key);
			pkgconf_buffer_append(buffer, ": ");

			if (pkgconfcli_serialize_is_value(obj_entry->value, PKGCONFCLI_SERIALIZE_TYPE_STRING))
				pkgconf_buffer_append(buffer, pkgconfcli_serialize_value_get_string(obj_entry->value));

			pkgconf_buffer_push_byte(buffer, '\n');
		}
		pkgconf_buffer_push_byte(buffer, '\n');
	}

	return true;

err:
	return false;
}
