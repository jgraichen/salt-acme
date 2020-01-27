FROM cznic/knot:2.8

COPY knot.conf /config/knot.conf
COPY example.com.zone example.org.zone /storage/

ENTRYPOINT [ "knotd" ]
