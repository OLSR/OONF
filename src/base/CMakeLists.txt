# create plugins for single-file (source plus header) subsystems
SET(SINGLE_FILE_NAMES    callback
                         class
                         clock
                         duplicate_set
                         http
                         layer2
                         packet_socket
                         socket
                         stream_socket
                         telnet
                         timer
                         viewer)

foreach(name ${SINGLE_FILE_NAMES})
    oonf_create_plugin("${name}" "oonf_${name}.c" "oonf_${name.h}" "")
endforeach(name)

# generate rfc5444 plugin
SET (linkto_internal oonf_librfc5444 oonf_libcore oonf_libconfig oonf_libcommon)
oonf_create_library("rfc5444" "oonf_rfc5444.c" "oonf_rfc5444.h" "${linkto_internal}" "")

# generate the os-specific plugins
# TODO: add BSD and WIN32

SET(OS_CLOCK_INCLUDE     os_clock.h)
SET(OS_INTERFACE_INCLUDE os_interface.h)
SET(OS_ROUTING_INCLUDE   os_routing.h)
SET(OS_FD_INCLUDE    os_fd.h)
SET(OS_SYSTEM_INCLUDE    os_system.h)
SET(OS_TUNNEL_INCLUDE    os_tunnel.h)
SET(OS_VIF_INCLUDE       os_vif.h)

IF(LINUX)
    SET(OS_CLOCK_SOURCE      os_linux/os_clock_linux.c)
    SET(OS_CLOCK_INCLUDE     ${OS_CLOCK_INCLUDE}
                             os_linus/os_clock_linux.h)
    
    SET(OS_INTERFACE_SOURCE  os_linux/os_interface_linux.c
                             os_generic/os_interface_generic.c)
    SET(OS_INTERFACE_INCLUDE ${OS_INTERFACE_INCLUDE}
                             os_linux/os_interface_linux.h
                             os_generic/os_interface_generic.h)

    SET(OS_ROUTING_SOURCE    os_generic/os_routing_generic_rt_to_string.c
                             os_generic/os_routing_generic_rtkey_avlcomp.c
                             os_generic/os_routing_generic_init_half_route_key.c
                             os_linux/os_routing_linux.c)
    SET(OS_ROUTING_INCLUDE   ${OS_ROUTING_INCLUDE}
                             os_linux/os_routing_linux.h)

    SET(OS_FD_SOURCE         os_generic/os_fd_generic_configsocket.c
                             os_generic/os_fd_generic_getsocket.c
                             os_generic/os_fd_generic_getrawsocket.c
                             os_generic/os_fd_generic_join_mcast.c
                             os_generic/os_fd_generic_set_nonblocking.c
                             os_generic/os_fd_generic_set_dscp.c
                             os_linux/os_fd_linux.c)
    SET(OS_FD_INCLUDE        ${OS_FD_INCLUDE}
                             os_generic/os_fd_generic_configsocket.h
                             os_generic/os_fd_generic_getsocket.h
                             os_generic/os_fd_generic_getrawsocket.h
                             os_generic/os_fd_generic_join_mcast.h
                             os_generic/os_fd_generic_set_nonblocking.h
                             os_generic/os_fd_generic_set_dscp.h
                             os_linux/os_fd_linux.h)

    SET(OS_SYSTEM_SOURCE     os_linux/os_system_linux.c)
    SET(OS_SYSTEM_INCLUDE    ${OS_SYSTEM_INCLUDE}
                             os_linux/os_system_linux.h)

    SET(OS_TUNNEL_SOURCE     os_linux/os_tunnel_linux.c)
    SET(OS_TUNNEL_INCLUDE    ${OS_TUNNEL_INCLUDE}
                             os_linux/os_tunnel_linux.h)

    SET(OS_VIF_SOURCE        os_linux/os_vif_linux.c)
    SET(OS_VIF_INCLUDE       os_linux/os_vif_linux.h)
ENDIF(LINUX)

# link librt to os_clock plugin to allow building with older GLIBC versions
# we need librt in the pluginloader anyways
oonf_create_plugin("os_clock" "${OS_CLOCK_SOURCE}" "${OS_CLOCK_INCLUDE}" "rt")
oonf_create_plugin("os_interface" "${OS_INTERFACE_SOURCE}" "${OS_INTERFACE_INCLUDE}" "")
oonf_create_plugin("os_routing" "${OS_ROUTING_SOURCE}" "${OS_ROUTING_INCLUDE}" "")
oonf_create_plugin("os_fd" "${OS_FD_SOURCE}" "${OS_FD_INCLUDE}" "")
oonf_create_plugin("os_system" "${OS_SYSTEM_SOURCE}" "${OS_SYSTEM_INCLUDE}" "")
oonf_create_plugin("os_tunnel" "${OS_TUNNEL_SOURCE}" "${OS_TUNNEL_INCLUDE}" "")
oonf_create_plugin("os_vif" "${OS_VIF_SOURCE}" "${OS_VIF_INCLUDE}" "")
