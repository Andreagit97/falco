// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#pragma once

#include "rule_loader.h"
#include "rule_loader_collector.h"
#include "logger.h"
#include "version.h"
#include "falco_engine_version.h"

// Error message used when both 'override' and 'append' are specified.
#define OVERRIDE_APPEND_ERROR_MESSAGE "Keys 'override' and 'append: true' cannot be used together. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

// Warning message used when `append` is used.
#define WARNING_APPEND_MESSAGE "'append' key is deprecated. Add an 'append' entry (e.g. 'condition: append') under 'override' instead."

// Warning message used when `enabled` is used without override.
#define WARNING_ENABLED_MESSAGE "The standalone 'enabled' key usage is deprecated. The correct approach requires also a 'replace' entry under the 'override' key (i.e. 'enabled: replace')."

namespace rule_loader
{

/*!
    \brief Reads the contents of a ruleset
*/
class reader
{
public:
    reader() = default;
    virtual ~reader() = default;
    reader(reader&&) = default;
	reader& operator = (reader&&) = default;
	reader(const reader&) = default;
	reader& operator = (const reader&) = default;

    /*!
		\brief Reads the contents of a ruleset and uses a collector to store
        thew new definitions
	*/
	virtual bool read(configuration& cfg, collector& loader);
    
    /*!
        \brief Engine version used to be represented as a simple progressive
	    number. With the new semver schema, the number now represents
	    the semver minor number. This function converts the legacy version 
	    number to the new semver schema.
    */
	static inline sinsp_version get_implicit_engine_version(uint32_t minor)
	{
		return sinsp_version(std::to_string(FALCO_ENGINE_VERSION_MAJOR) + "."
			+ std::to_string(minor) + "." 
			+ std::to_string(FALCO_ENGINE_VERSION_PATCH));
	}
};

}; // namespace rule_loader
