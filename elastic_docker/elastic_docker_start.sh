#!/bin/bash
set -e

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:8.15.0"
KB_IMAGE="docker.elastic.co/kibana/kibana:8.15.0"
NETWORK="elk"
PASSWORD="3LYN_virPJ_TzasQ65qH"

echo "Creating Docker network (if missing)..."
docker network create $NETWORK 2>/dev/null || true

echo "Starting Elasticsearch..."
docker run -d \
  --name elasticsearch \
  --net $NETWORK \
  -p 9200:9200 \
  -e discovery.type=single-node \
  -e ELASTIC_PASSWORD="$PASSWORD" \
  $ES_IMAGE

echo "Waiting for Elasticsearch to become ready..."
until curl -k -s -o /dev/null -w "%{http_code}" https://localhost:9200 -u elastic:$PASSWORD | grep 200 > /dev/null; do
  echo "  ... still waiting"
  sleep 3
done
echo "Elasticsearch is ready."

echo "Creating Kibana service token..."
RAW_OUTPUT=$(docker exec elasticsearch elasticsearch-service-tokens create elastic/kibana kibana_token)

SERVICE_TOKEN=$(echo "$RAW_OUTPUT" | awk -F'= ' '/kibana_token/ {print $2}')

echo "Service Token: $SERVICE_TOKEN"

echo "Starting Kibana..."
docker run -d \
  --name kibana \
  --net $NETWORK \
  -p 5601:5601 \
  -e ELASTICSEARCH_HOSTS="https://elasticsearch:9200" \
  -e ELASTICSEARCH_SERVICEACCOUNTTOKEN="$SERVICE_TOKEN" \
  -e ELASTICSEARCH_SSL_VERIFICATIONMODE="none" \
  $KB_IMAGE

echo ""
echo "🚀 Services started:"
echo "Elasticsearch → https://localhost:9200"
echo "Kibana        → http://localhost:5601"
