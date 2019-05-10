# set source files
SET (radio_only_source  ext_base_proto/proto_radio.c
                        radio/dlep_radio.c
                        radio/dlep_radio_interface.c
                        radio/dlep_radio_session.c) 
SET (router_only_source ext_base_proto/proto_router.c
                        router/dlep_router.c
                        router/dlep_router_interface.c
                        router/dlep_router_session.c)
SET (common_source      ext_base_metric/metric.c
                        ext_base_ip/ip.c
                        ext_base_proto/proto.c
                        ext_l1_statistics/l1_statistics.c
                        ext_l2_statistics/l2_statistics.c
                        ext_radio_attributes/radio_attributes.c
                        ext_lid/lid.c
                        ext_dns/dns.c
                        dlep_extension.c
                        dlep_interface.c
                        dlep_session.c
                        dlep_reader.c
                        dlep_writer.c)

# sources/includes for dlep_radio                    
SET (radio_source       ${common_source}
                        ${radio_only_source})
SET (radio_include      radio/dlep_radio.h)

# sources/includes for dlep_router
SET (router_source      ${common_source}
                        ${router_only_source})
SET (router_include     router/dlep_router.h)

# sources/includes for dlep_proxy
SET (proxy_source       ${common_source}
                        ${radio_only_source}
                        ${router_only_source})
SET (proxy_include      ${radio_include}
                        ${router_include})

# use generic plugin maker for dlep-radio
oonf_create_plugin("dlep_radio" "${radio_source}" "${radio_include}" "")

# use generic plugin maker for dlep-router
oonf_create_plugin("dlep_router" "${router_source}" "${router_include}" "")

# combined radio/router plugin
oonf_create_plugin("dlep_proxy" "${proxy_source}" "${proxy_include}" "")
