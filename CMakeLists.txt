idf_component_register(SRCS "src/parse.c" "src/smolcert.c" "src/validate.c"
                       INCLUDE_DIRS "include"
                       REQUIRES cbor libsodium)
