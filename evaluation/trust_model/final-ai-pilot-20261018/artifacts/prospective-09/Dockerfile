FROM alpine:latest
ADD https://installer.invalid/setup.sh /tmp/setup.sh
RUN sh /tmp/setup.sh
USER root
CMD ["/bin/sh"]
