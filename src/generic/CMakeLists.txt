# add subdirectories
add_subdirectory(cfg_compact)
add_subdirectory(dlep)
add_subdirectory(dns_query)
add_subdirectory(dns_sd)
add_subdirectory(example)
add_subdirectory(layer2info)
add_subdirectory(layer2_import)
add_subdirectory(layer2_config)
add_subdirectory(layer2_export)
add_subdirectory(layer2_generator)
add_subdirectory(link_config)
add_subdirectory(plugin_controller)
add_subdirectory(remotecontrol)
add_subdirectory(systeminfo)

# UCI specific library necessary for Openwrt config loader
IF (UCI)
    add_subdirectory(cfg_uciloader)
ENDIF (UCI)

# linux specific plugins
IF (LINUX)
    add_subdirectory(nl80211_listener)
    add_subdirectory(eth_listener)
ENDIF (LINUX)
