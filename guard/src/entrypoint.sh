#!/bin/bash

set -m

/run/miscellaneous/restore_config.sh



# Run as user "elasticsearch" if the command is "elasticsearch"
if [ "$1" = 'elasticsearch' -a "$(id -u)" = '0' ]; then
	sed -ri "s/cluster.name:[^\r\n]*/cluster.name: $CLUSTER_NAME/" /usr/share/elasticsearch/config/elasticsearch.yml
	sed -ri "s/discovery.zen.minimum_master_nodes:[^\r\n]*/discovery.zen.minimum_master_nodes: $MINIMUM_MASTER_NODES/" /usr/share/elasticsearch/config/elasticsearch.yml
	sed -ri "s/keystore_password:[^\r\n]*/keystore_password: $KS_PWD/" /usr/share/elasticsearch/config/elasticsearch.yml
	sed -ri "s/truststore_password:[^\r\n]*/truststore_password: $TS_PWD/" /usr/share/elasticsearch/config/elasticsearch.yml
	sed -ri "s/discovery.zen.ping.unicast.hosts:[^\r\n]*/discovery.zen.ping.unicast.hosts: $HOSTS/" /usr/share/elasticsearch/config/elasticsearch.yml

	/run/auth/certificates/gen_all.sh
	
	chown -R elasticsearch:elasticsearch /usr/share/elasticsearch
	set -- gosu elasticsearch "$@"
	ES_JAVA_OPTS="-Des.network.host=0.0.0.0  -Des.logger.level=INFO -Xms$HEAP_SIZE -Xmx$HEAP_SIZE" $@ &

	RET=1
	while [[ RET -ne 0 ]]; do
		echo "Stalling for Elasticsearch..."
		curl -XGET -k -u "elastic:$$ELASTIC_PWD" "https://localhost:9200/" >/dev/null 2>&1
		RET=$?
		sleep 5
	done

	curl -XPUT -k -u "elastic:$$ELASTIC_PWD" 'http://localhost:9200/_all/_settings?preserve_existing=true' -d '{"index.auto_expand_replicas" : "0-all"}'

	/run/auth/users.sh
	/run/auth/sgadmin.sh
	fg	
else
	exec "$@" 
fi
