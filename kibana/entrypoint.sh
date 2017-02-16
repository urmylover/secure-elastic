#!/bin/bash

set -m

/run/miscellaneous/restore_config.sh
/run/miscellaneous/edit_config.sh
/run/miscellaneous/wait_for_elasticsearch.sh

if [ "$KIBANA_PWD" ]; then
    sed -ri "s|elasticsearch.password:[^\r\n]*|elasticsearch.password: $KIBANA_PWD|" /etc/kibana/kibana.yml
fi

if [ "$ELASTICSEARCH_URL" ]; then
    sed -ri "s!^(\#\s*)?(elasticsearch\.url:).*!\2 '$ELASTICSEARCH_URL'!" /etc/kibana/kibana.yml
    RET=1
    while [[ RET -ne 0 ]]; do
        echo "Kibana is Stalling for Elasticsearch..."
        curl -XGET -k -u "kibana:$KIBANA_PWD" "$ELASTICSEARCH_URL" >/dev/null 2>&1
        RET=$?
        sleep 5
    done
fi
# Run as user "logstash" if the command is "kibana"
if [ "$1" = 'kibana' ]; then
	set -- gosu kibana tini -- "$@"
fi
$@ &

fg