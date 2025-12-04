# set library parameters
SET (name dns_sd)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
