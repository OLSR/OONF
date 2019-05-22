###########################################
#### Default Application configuration ####
###########################################

# set name of program the executable and library prefix
set (OONF_APP "OLSRd2 DLEP")
set (OONF_EXE olsrd2_dlep)

# setup custom text before and after default help message
set (OONF_HELP_PREFIX "OLSRv2 routing agent with DLEP\\n")
set (OONF_HELP_SUFFIX "Visit http://www.olsr.org\\n")

# setup custom text after version string
set (OONF_VERSION_TRAILER "Visit http://www.olsr.org\\n")

# set to true to stop application running without root privileges (true/false)
set (OONF_NEED_ROOT true)

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
                             duplicate_set
                             layer2
                             packet_socket
                             rfc5444
                             socket
                             stream_socket
                             telnet
                             timer
                             viewer
                             os_clock
                             os_fd
                             os_interface
                             os_routing
                             os_system
                             cfg_compact
                             layer2info
                             systeminfo
                             nhdp
                             ff_dat_metric
                             layer2_config
                             neighbor_probing
                             nhdpinfo
                             olsrv2
                             olsrv2info
                             olsrv2_lan
                             netjsoninfo
                             layer2_import
                             auto_ll4
                             http
                             dlep
                             )
ENDIF (NOT OONF_STATIC_PLUGINS)


IF (NOT OONF_OPTIONAL_STATIC_PLUGINS)
    set (OONF_OPTIONAL_STATIC_PLUGINS nl80211_listener)
ENDIF (NOT OONF_OPTIONAL_STATIC_PLUGINS)

##################################
#### link framework libraries ####
##################################

include(../../cmake/link_app.cmake)
oonf_create_app("${OONF_EXE}" "${OONF_STATIC_PLUGINS}" "${OONF_OPTIONAL_STATIC_PLUGINS}")
