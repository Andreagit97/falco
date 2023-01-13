/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <nlohmann/json.hpp>

#include "application.h"
#include "versions_info.h"

using namespace falco::app;

application::run_result application::print_version()
{
	if(m_options.print_version_info)
	{
		const versions_info info(m_state->offline_inspector);
		if(m_state->config->m_json_output)
		{
			printf("%s\n", info.as_json().dump().c_str());
		}
		else
		{
			printf("Falco version: %s\n", info.falco_version.c_str());
			printf("Libs version:  %s\n", info.libs_version.c_str());
			printf("Plugin API:    %s\n", info.plugin_api_version.c_str());
			printf("Engine:        %s\n", info.engine_version.c_str());
			printf("Driver:\n");
			printf("  API version:    %s\n", info.driver_api_version.c_str());
			printf("  Schema version: %s\n", info.driver_schema_version.c_str());
			printf("  Default driver: %s\n", info.default_driver_version.c_str());
		}
		return run_result::exit();
	}

	return run_result::ok();
}
