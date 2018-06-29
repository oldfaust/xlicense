#!/bin/bash

# Such options need /jre/lib/amd64/libmanagement.so to be added
# to the JRE which adds about 50K uncompressed size.
# Can be added if passing options to Java is actually needed.
# -Xmx100m \
# -Xss2048k \

java \
    -jar jruby-complete.jar \
    xappldr.class -R ./enc.bin -C "-C q -P ./test" -B 192.168.56.101
