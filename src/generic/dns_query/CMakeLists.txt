# set library parameters
SET (name dns_query)

SET (source dns.c
            dns_query.c
    )

SET (headers dns.h
             dns_query.h
    )

# use generic plugin maker
oonf_create_plugin("${name}" "${source}" "${headers}" "")
