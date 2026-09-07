FROM alpine:3.22.1

RUN apk add --no-cache tcpreplay \
    && addgroup -S -g 65532 replay \
    && adduser -S -D -H -u 65532 -G replay replay

USER 65532:65532

ENTRYPOINT ["tcpreplay"]
