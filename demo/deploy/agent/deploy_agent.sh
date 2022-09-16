#!/usr/bin/env bash
set -e

SHORT=r::,p::,h
LONG=region::,project_id::,help
OPTS=$(getopt -a --options $SHORT --longoptions $LONG -- "$@")

help()
{
    echo "Usage: deploy_agent [ -r | --region     ]
                    [ -p | --project_id ]
                    [ -h | --help       ]"

    exit 2
}

VALID_ARGUMENTS=$#

if [ "$VALID_ARGUMENTS" -eq 0 ]; then
  help
fi

eval set -- "$OPTS"

while :
do
  case "$1" in
    -r | --region )
      REGION="$2"
      shift 2
      ;;
    -p | --project_id )
      PROJECT_ID="$2"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done

echo $REGION
echo $PROJECT_ID

curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID?}" \
  -d \
  '{
    "displayName": "Telecommunications",
    "defaultLanguageCode": "en",
    "timeZone": "America/Chicago"
  }' \
  "https://${REGION?}-dialogflow.googleapis.com/v3/projects/${PROJECT_ID?}/locations/${REGION?}/agents"

AGENT_NAME=$(curl -s -X GET -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID}" \
  "https://${REGION?}-dialogflow.googleapis.com/v3/projects/${PROJECT_ID?}/locations/${REGION?}/agents" | jq -r '.agents[0].name')

curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID?}" \
  -d \
  '{
    "agentUri": "gs://gassets-api-ai/prebuilt_agents/cx-prebuilt-agents/exported_agent_Telecommunications.blob"
  }' \
  "https://${REGION?}-dialogflow.googleapis.com/v3/${AGENT_NAME?}:restore"