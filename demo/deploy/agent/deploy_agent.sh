#!/usr/bin/env bash
set -e

SHORT=r::,p::,w::,h
LONG=region::,project_id::,webhook_name::,help
OPTS=$(getopt -a --options $SHORT --longoptions $LONG -- "$@")

help()
{
    echo "Usage: deploy_agent [ -r | --region     ]
                    [ -p | --project_id   ]
                    [ -w | --webhook_name ]
                    [ -h | --help         ]"
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
    -w | --webhook_name )
      WEBHOOK_NAME="$2"
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

WEBHOOK_TRIGGER_URI="https://${REGION?}-${PROJECT_ID?}.cloudfunctions.net/${WEBHOOK_NAME?}"

echo 'Creating agent...'
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
echo '  Done creating agent.'

echo 'Getting agent name...'
AGENT_FULL_NAME=$(curl -s -X GET -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID}" \
  "https://${REGION?}-dialogflow.googleapis.com/v3/projects/${PROJECT_ID?}/locations/${REGION?}/agents" | jq -r '.agents[0].name')
echo '  Done getting agent name.'

echo 'Restoring agent...'
curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID?}" \
  -d \
  '{
    "agentUri": "gs://gassets-api-ai/prebuilt_agents/cx-prebuilt-agents/exported_agent_Telecommunications.blob"
  }' \
  "https://${REGION?}-dialogflow.googleapis.com/v3/${AGENT_FULL_NAME?}:restore"
echo '  Done restoring agent.'

echo 'Getting webhook name...'
WEBHOOK_FULL_NAME=$(curl -s -X GET \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "x-goog-user-project: ${PROJECT_ID?}" \
  "https://${REGION?}-dialogflow.googleapis.com/v3/${AGENT_FULL_NAME?}/webhooks" | jq -r '.webhooks[0].name')
echo '  Done getting webhook name.'

echo 'Setting webhook fulfillment to Cloud Function...'
curl -s -X PATCH \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type:application/json" \
  -H "x-goog-user-project: ${PROJECT_ID?}" \
  -d \
  "{
    \"displayName\": \"cxPrebuiltAgentsTelecom\",
    \"genericWebService\": {\"uri\": \"${WEBHOOK_TRIGGER_URI?}\"}
  }" \
  "https://${REGION?}-dialogflow.googleapis.com/v3/${WEBHOOK_FULL_NAME?}"
echo '  Done setting webhook fulfillment to Cloud Function.'