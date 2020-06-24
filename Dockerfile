FROM docker.io/alpine:latest

LABEL maintainer "OWenT <admin@owent.net>"

RUN mkdir -p /opt/wxwork_robotd

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/wxwork_robotd/bin

COPY "./bin" "/opt/wxwork_robotd/"
COPY "./etc" "/opt/wxwork_robotd/"
COPY "./tools" "/opt/wxwork_robotd/"

CMD ["wxwork_robotd", "-c", "/opt/wxwork_robotd/etc/conf.json"]