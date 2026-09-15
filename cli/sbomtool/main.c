/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 *​ Copyright (c) 2026 The FreeBSD Foundation
 *​
 *​ Portions of this software were developed by
 * Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from
 * the FreeBSD Foundation
 */

#include "libpkgconf/config.h"
#include <libpkgconf/stdinc.h>
#include <libpkgconf/libpkgconf.h>
#include "getopt_long.h"
#include "serialize.h"
#include "cyclonedx/component.h"
#include "cyclonedx/metadata.h"
#include "cyclonedx/dependencies.h"
#include "cyclonedx/structure.h"
#include "util.h"

#define PKG_VERSION			(((uint64_t) 1) << 1)
#define PKG_ABOUT			(((uint64_t) 1) << 2)
#define PKG_HELP			(((uint64_t) 1) << 3)

static int maximum_traverse_depth = 2000;

static pkgconf_client_t pkg_client;
static uint64_t want_flags;
// static int maximum_traverse_depth = 2000;
static FILE *error_msgout = NULL;
static FILE *sbom_out = NULL;

#define SBOM_TOOL_URL_DEFAULT "https://github.com/pkgconf/pkgconf"
#define SBOM_TOOL_URI_DEFAULT "pkgconf"

static const char *
environ_lookup_handler(const pkgconf_client_t *client, const char *key)
{
	(void) client;

	return getenv(key);
}

static bool
error_handler(const char *msg, const pkgconf_client_t *client, void *data)
{
	(void) client;
	(void) data;
	if (!pkgconf_output_file_fmt(error_msgout, "%s", msg))
	{
		pkgconf_error(client, "spdxtool: Could not output error message: %s", strerror(errno));
		return false;
	}
	return true;
}

static int
version(void)
{
	printf("spdxtool %s\n", PACKAGE_VERSION);
	return EXIT_SUCCESS;
}

static int
about(void)
{
	printf("spdxtool (%s %s)\n\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf("SPDX-License-Identifier: BSD-2-Clause\n\n");
	printf("Copyright (c) 2025 The FreeBSD Foundation\n\n");
	printf("Portions of this software were developed by\n");
	printf("Tuukka Pasanen <tuukka.pasanen@ilmi.fi> under sponsorship from\n");
	printf("the FreeBSD Foundation\n\n");
	printf("Report bugs at <%s>.\n", PACKAGE_BUGREPORT);
	return EXIT_SUCCESS;
}

static int
usage(void)
{
	printf("usage: spdxtool [modules]\n");

	printf("\nOptions:\n");

	printf("  --agent-name                      Set agent name [default: 'Default']\n");
	printf("  --creation-time                   Use string as creation time (Should be in ISO8601 format) [default: current time]\n");
	printf("  --creation-id                     Use string as creation id [default: '_:creationinfo_1']\n");
	printf("  --help                            this message\n");
	printf("  --about                           print spdxtool version and license to stdout\n");
	printf("  --version                         print spdxtool version to stdout\n");
	printf("  --output FILE                     output SBOM data to file\n");
	//printf("  --sbom-base-id URL                Uset string as base of SPDX ids [default: %s]\n", xsd_any_uri_default_base);
	printf("  --use-uri                         Use URIs not URLs as SPDX id");
	printf("  --define-variable=varname=value   define variable global 'varname' as 'value'\n");

	return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	pkgconf_list_t pkgq = PKGCONF_LIST_INITIALIZER;
	unsigned int want_client_flags = PKGCONF_PKG_PKGF_SEARCH_PRIVATE;
	pkgconf_cross_personality_t *personality = pkgconf_cross_personality_default();
	char world_id[] = "virtual:world";
	char world_realname[] = "virtual world package";
	const char *sbom_id_base = SBOM_TOOL_URL_DEFAULT;
	bool colon_sep = false;
	pkgconf_pkg_t world =
	{
		.id = world_id,
		.realname = world_realname,
		.flags = PKGCONF_PKG_PROPF_STATIC | PKGCONF_PKG_PROPF_VIRTUAL,
	};
	const char *creation_time = NULL;
	const char *agent_name = NULL;
	const char *agent_url = NULL;
	bool is_tool = false;

	error_msgout = stderr;
	sbom_out = stdout;

	struct pkgconfcli_option options[] =
	{
		{ "agent-name", required_argument, NULL, 100, },
		{ "agent-url", required_argument, NULL, 101, },
		{ "creation-time", required_argument, NULL, 102, },
		{ "creation-id", required_argument, NULL, 103, },
		{ "enable-tool-name", no_argument, NULL, 104},
		{ "version", no_argument, &want_flags, PKG_VERSION, },
		{ "about", no_argument, &want_flags, PKG_ABOUT, },
		{ "help", no_argument, &want_flags, PKG_HELP, },
		{ "output", required_argument, NULL, 105, },
		{ "sbom-base-id", required_argument, NULL, 106, },
		{ "use-uri", no_argument, NULL, 107, },
		{ "define-variable", required_argument, NULL, 108, },
		{ NULL, 0, NULL, 0 }
	};

	while ((ret = pkgconfcli_getopt_long_only(argc, argv, "", options, NULL)) != -1)
	{
		switch (ret)
		{
		case 100:
			agent_name = pkgconfcli_optarg;
			break;
		case 101:
			agent_url = pkgconfcli_optarg;
			break;
		case 102:
			creation_time = pkgconfcli_optarg;
			break;
		/*case 103:
			creation_id = pkgconfcli_optarg;
			break;*/
		case 104:
			is_tool = true;
			break;
		case 105:
			sbom_out = fopen(pkgconfcli_optarg, "w");
			if (sbom_out == NULL)
			{
				pkgconf_output_file_fmt(stderr, "unable to open %s: %s\n", pkgconfcli_optarg, strerror(errno));
				return EXIT_FAILURE;
			}
			break;
		case 106:
			sbom_id_base = pkgconfcli_optarg;
			break;
		case 107:
			// If SPDX id base have not been altered use default
			if (!strcmp(sbom_id_base, SBOM_TOOL_URL_DEFAULT))
			 	sbom_id_base = SBOM_TOOL_URI_DEFAULT;
			colon_sep = true;
			break;
		case 108:
			pkgconf_tuple_define_global(&pkg_client, pkgconfcli_optarg);
			break;
		case '?':
		case ':':
			return EXIT_FAILURE;
		default:
			break;
		}
	}

	if (!agent_name)
		agent_name = "Default";

	if (!agent_url)
		agent_url = SBOM_TOOL_URL_DEFAULT;

	pkgconf_client_options_t client_options = {
		.error_handler = error_handler,
		.personality = personality,
		.environ_lookup_handler = environ_lookup_handler,
	};
	pkgconf_client_init_with_options(&pkg_client, &client_options);

	/* we have determined what features we want most likely.  in some cases, we override later. */
	pkgconf_client_set_flags(&pkg_client, want_client_flags);

	/* at this point, want_client_flags should be set, so build the dir list */
	pkgconf_client_dir_list_build(&pkg_client, personality);


	if ((want_flags & PKG_ABOUT) == PKG_ABOUT)
		return about();

	if ((want_flags & PKG_VERSION) == PKG_VERSION)
		return version();

	if ((want_flags & PKG_HELP) == PKG_HELP)
		return usage();

	/* Join the remaining arguments into a single query string, as the main
	 * pkgconf CLI does, and let the dependency parser handle module names,
	 * comparison operators and versions.
	 */
	pkgconf_buffer_t queryparams = PKGCONF_BUFFER_INITIALIZER;

	while (pkgconfcli_optind < argc && argv[pkgconfcli_optind] != NULL)
	{
		if ((pkgconf_buffer_len(&queryparams) > 0 &&
			 !pkgconf_buffer_push_byte(&queryparams, ' ')) ||
			!pkgconf_buffer_append(&queryparams, argv[pkgconfcli_optind]))
		{
			pkgconf_buffer_finalize(&queryparams);
			ret = EXIT_FAILURE;
			goto out;
		}

		pkgconfcli_optind++;
	}

	if (pkgconf_buffer_len(&queryparams) > 0)
		pkgconf_queue_push(&pkgq, pkgconf_buffer_str(&queryparams));

	pkgconf_buffer_finalize(&queryparams);

	if (pkgq.head == NULL)
	{
		pkgconf_output_file_fmt(stderr, "Please specify at least one package name on the command line.\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (!pkgconf_queue_solve(&pkg_client, &pkgq, &world, maximum_traverse_depth))
	{
		ret = EXIT_FAILURE;
		goto out;
	}

	sbomtool_util_set_uri_root(&pkg_client, sbom_id_base);
	sbomtool_util_set_uri_separator_colon(&pkg_client, colon_sep);


	pkgconfcli_serialize_value_t *cyclonedx_doc = sbomtool_cyclonedx_structure_new(&pkg_client, 1);
	sbomtool_cyclonedx_structure_add_metadata(&pkg_client, cyclonedx_doc, creation_time, agent_name, agent_url, is_tool);


	int eflag = pkgconf_pkg_traverse(&pkg_client, &world, sbomtool_cyclondex_component_add_package, cyclonedx_doc, 2000, 0);
	if (eflag != PKGCONF_PKG_ERRF_OK)
	{
		ret = EXIT_FAILURE;
		goto out;
	}
	pkgconf_buffer_t buffer = PKGCONF_BUFFER_INITIALIZER;
	bool bool_ret = pkgconfcli_serialize_value_to_buf(&buffer, cyclonedx_doc, 0);
	pkgconfcli_serialize_value_free(cyclonedx_doc);

	if (bool_ret)
	{
		bool_ret = pkgconf_output_file_fmt(sbom_out, "%s\n", pkgconf_buffer_str(&buffer));
		if (!bool_ret)
			pkgconf_error(&pkg_client, "spdxtool: Could not output to file: %s", strerror(errno));
	}
	else
		pkgconf_error(&pkg_client, "spdxtool: Could not serialize SPDX document");

	pkgconf_buffer_finalize(&buffer);

	ret = EXIT_SUCCESS;

out:
	pkgconf_solution_free(&pkg_client, &world);
	pkgconf_queue_free(&pkgq);
	pkgconf_cross_personality_deinit(personality);
	pkgconf_client_deinit(&pkg_client);

	return ret;
}
