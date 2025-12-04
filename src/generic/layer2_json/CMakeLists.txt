# set library parameters
INCLUDE(FindPkgConfig)

pkg_check_modules(LIBJANSSON jansson)
if (LIBJANSSON_FOUND)
        include_directories(${LIBJANSSON_INCLUDE_DIRS})
        link_directories(${LIBJANSSON_LIBRARY_DIRS})

        # set library parameters
        SET (srcs layer2json.c l2json_import.c l2json_export.c)
        SET (hdrs layer2_json.h layer2_json_internal.h)

        message(STATUS "Using '${LIBJANSSON_LIBRARIES}' for json handling")

        # use generic plugin maker
        oonf_create_plugin("layer2_json" "${srcs}" "${hdrs}" "${LIBJANSSON_LIBRARIES}")
endif (LIBJANSSON_FOUND)
