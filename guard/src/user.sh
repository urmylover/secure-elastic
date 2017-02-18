#!/bin/sh
USER=$1
# HASH=$(docker run -it --rm newfuture/secure-elastic /usr/share/elasticsearch/plugins/search-guard-5/tools/hash.sh $2)
HASH=$(bash /usr/share/elasticsearch/plugins/search-guard-5/tools/hash.sh -p $2)
ROLES=${3:-admin}

FILE=${4:-"/usr/share/elasticsearch/config/searchguard/sg_internal_users.yml"}
CONFIG="$USER:\n  hash: '$HASH' #$USER\n  roles:\n   - $ROLES"
LINE=$(grep -n "^$USER:$" $FILE | awk -F: '{print $1}')
if [ $LINE ];then
    echo "modify user $USER [$ROLES]"
    sed -i "/^$USER:/,+3d" $FILE
    sed -i "$LINE i $CONFIG" $FILE
else
    echo "add user $USER [$ROLES]"
    echo "\n$CONFIG\n" >> $FILE
fi

