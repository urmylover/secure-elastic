#!/bin/bash

set -m

if [ "$KIBANA_PWD" ]; then
    sed -ri "s|elasticsearch.password:[^\r\n]*|elasticsearch.password: $KIBANA_PWD|" /etc/kibana/kibana.yml
fi

if [ "$ELASTICSEARCH_URL" ]; then
    sed -ri "s!^(\#\s*)?(elasticsearch\.url:).*!\2 '$ELASTICSEARCH_URL'!" /etc/kibana/kibana.yml
    RET=4
    while [[ "$RET" != "4" ]]; do
        echo "Kibana is Stalling for Elasticsearch $ELASTICSEARCH_URL ..."
        wget -T 60 -c -q "$ELASTICSEARCH_URL" --no-check-certificate; RET=$?
        # echo $RET
        sleep 5
    done
fi

# Add kibana as command if needed
if [[ "$1" == -* ]]; then
	set -- kibana "$@"
fi

# Run as user "logstash" if the command is "kibana"
if [ "$1" = 'kibana' ]; then
	set -- gosu kibana tini -- "$@"
fi

exec "$@"