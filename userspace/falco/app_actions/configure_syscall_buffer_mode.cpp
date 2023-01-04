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

#include "application.h"

using namespace falco::app;

application::run_result application::configure_syscall_buffer_mode()
{
    /* we can configure the buffer mode only with modern BPF engine */
    if(!m_options.modern_bpf)
    {
        return run_result::ok();
    }

	if(m_state->config->m_syscall_buf_mode_string.compare(MODERN_PER_CPU_BUFFER_NAME) == 0)
    {
        m_state->syscall_buffer_mode = MODERN_PER_CPU_BUFFER;
    }
    else if(m_state->config->m_syscall_buf_mode_string.compare(MODERN_PAIRED_BUFFER_NAME) == 0)
    {
        m_state->syscall_buffer_mode = MODERN_PAIRED_BUFFER;
    }
    else if(m_state->config->m_syscall_buf_mode_string.compare(MODERN_SINGLE_BUFFER_NAME) == 0)
    {
        m_state->syscall_buffer_mode = MODERN_SINGLE_BUFFER;
    }
    else
    {
        return run_result::fatal("'" + m_state->config->m_syscall_buf_mode_string + "' is not a valid value for 'syscall_buf_mode'\n");
    }
	return run_result::ok();
}
