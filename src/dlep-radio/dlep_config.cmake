###########################################
#### Default Application configuration ####
###########################################

# set name of program the executable and library prefix
set (OONF_APP "DLEP Radio")
set (OONF_EXE dlep_radio)

# setup custom text before and after default help message
set (OONF_HELP_PREFIX "DLEP Radio daemon\\n")
set (OONF_HELP_SUFFIX "Visit http://www.olsr.org\\n")

# setup custom text after version string
set (OONF_VERSION_TRAILER "Visit http://www.olsr.org\\n")

# set to true to stop application running without root privileges (true/false)
set (OONF_NEED_ROOT true)

# name of default configuration handler
set (OONF_APP_DEFAULT_CFG_HANDLER Compact)

#################################
####  set static subsystems  ####
#################################

set (OONF_STATIC_PLUGINS class
                         clock
                         interface
                         layer2
                         packet_socket
                         socket
                         stream_socket
                         telnet
                         timer
                         viewer
                         os_clock
                         os_socket
                         os_interface
                         os_system
                         cfg_compact
                         layer2info
                         nl80211_listener
                         systeminfo
                         dlep_radio
                         )
