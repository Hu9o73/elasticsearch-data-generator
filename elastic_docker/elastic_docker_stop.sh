#!/bin/bash

echo "Stopping Kibana..."
docker stop kibana 2>/dev/null
docker rm kibana 2>/dev/null

echo "Stopping Elasticsearch..."
docker stop elasticsearch 2>/dev/null
docker rm elasticsearch 2>/dev/null

# echo "Removing images..."
# docker rmi docker.elastic.co/kibana/kibana:8.15.0 2>/dev/null
# docker rmi docker.elastic.co/elasticsearch/elasticsearch:8.15.0 2>/dev/null

echo "Removing Docker network..."
docker network rm elk 2>/dev/null

echo ""
echo "🧹 Cleanup complete."
