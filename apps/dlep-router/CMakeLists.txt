###########################################
#### Default Application configuration ####
###########################################

# set name of program the executable and library prefix
set (OONF_APP "DLEP Router")
set (OONF_EXE dlep_router)

# setup custom text before and after default help message
set (OONF_HELP_PREFIX "DLEP Router daemon\\n")
set (OONF_HELP_SUFFIX "Visit http://www.olsr.org\\n")

# setup custom text after version string
set (OONF_VERSION_TRAILER "Visit http://www.olsr.org\\n")

# set to true to stop application running without root privileges (true/false)
set (OONF_NEED_ROOT false)

# set to true to require a lock for the application to run
set (OONF_NEED_LOCK true)

# name of default configuration handler
set (OONF_APP_DEFAULT_CFG_HANDLER Compact)

#################################
####  set static subsystems  ####
#################################

IF (NOT OONF_STATIC_PLUGINS)
    set (OONF_STATIC_PLUGINS class
                             clock
                             layer2
                             packet_socket
                             socket
                             stream_socket
                             telnet
                             http
                             timer
                             viewer
                             os_clock
                             os_fd
                             os_interface
                             os_system
                             os_routing
                             cfg_compact
                             layer2info
                             systeminfo
                             remotecontrol
                             layer2_config
                             layer2_export
                             dns_query
                             dns_sd
                             dlep_router
                             )
ENDIF (NOT OONF_STATIC_PLUGINS)

##################################
#### link framework libraries ####
##################################

include(../../cmake/link_app.cmake)
oonf_create_app("${OONF_EXE}" "${OONF_STATIC_PLUGINS}" "${OONF_OPTIONAL_STATIC_PLUGINS}")
