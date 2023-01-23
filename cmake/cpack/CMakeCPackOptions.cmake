if(CPACK_GENERATOR MATCHES "DEB" OR CPACK_GENERATOR MATCHES "RPM")
	list(APPEND CPACK_INSTALL_COMMANDS "mkdir -p _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-kmod-inject.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-kmod.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-bpf.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-modern-bpf.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falco-plugin.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
	list(APPEND CPACK_INSTALL_COMMANDS "cp scripts/systemd/falcoctl-artifact-follow.service _CPack_Packages/${CPACK_TOPLEVEL_TAG}/${CPACK_GENERATOR}/${CPACK_PACKAGE_FILE_NAME}/usr/lib/systemd/system")
endif()

if(CPACK_GENERATOR MATCHES "TGZ")
	set(CPACK_SET_DESTDIR "ON")
endif()
