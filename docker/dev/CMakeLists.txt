# Build a docker container for Falco no-driver
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(FALCO_DOCKER_CONTEXT ${CMAKE_BINARY_DIR}/docker/falco-docker-ctx)

  # This target prepares the tar.gz artifact that will be passed to the dockerfile.
  add_custom_target(falco-docker-context
    COMMAND mkdir -p ${FALCO_DOCKER_CONTEXT}
    COMMAND make package
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/falco-${FALCO_VERSION}-${FALCO_TARGET_ARCH}.tar.gz ${FALCO_DOCKER_CONTEXT}/falco.tar.gz
    DEPENDS falco
  )

  # Here we can build both the falco-driver-loader and the no-driver
  add_custom_target(falco-container
    COMMAND docker build
      --tag falco-no-driver:dev
      -f ${CMAKE_SOURCE_DIR}/docker/dev/falco-no-driver.Dockerfile
      ${FALCO_DOCKER_CONTEXT}
    DEPENDS falco-docker-context
  )
endif()
