# set source files
SET (source             ext_base_metric/metric.c
                        ext_base_ip/ip.c
                        ext_base_proto/proto.c
                        ext_base_proto/proto_router.c
                        ext_base_proto/proto_radio.c
                        ext_l1_statistics/l1_statistics.c
                        ext_l2_statistics/l2_statistics.c
                        ext_radio_attributes/radio_attributes.c
                        ext_lid/lid.c
                        ext_dns/dns.c
                        router/dlep_router_interface.c
                        router/dlep_router_session.c
                        radio/dlep_radio_interface.c
                        radio/dlep_radio_session.c
                        dlep_extension.c
                        dlep_interface.c
                        dlep_reader.c
                        dlep_session.c
                        dlep_telnet.c
                        dlep_writer.c
                        dlep.c)

# sources/includes for dlep
SET (include            dlep_extension.h
                        dlep_iana.h
                        dlep_interface.h
                        dlep_reader.h
                        dlep_session.h
                        dlep_telnet.h
                        dlep_writer.h
                        dlep.h)

# use generic plugin maker for dlep-radio
oonf_create_plugin("dlep" "${source}" "${include}" "")
