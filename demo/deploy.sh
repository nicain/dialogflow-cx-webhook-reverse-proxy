#!/usr/bin/env bash
set -e

SHORT=t::,h
LONG=tag::,help
OPTS=$(getopt -a -n weather --options $SHORT --longoptions $LONG -- "$@")

help()
{
    echo "Usage: deploy [ -t | --tag ]
              [ -h | --help  ]"

    exit 2
}

VALID_ARGUMENTS=$# # Returns the count of arguments that are in short or long options

if [ "$VALID_ARGUMENTS" -eq 0 ]; then
  help
fi

eval set -- "$OPTS"

while :
do
  case "$1" in
    -t | --tag )
      SERVICE_TAG="$2"
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

export IMAGE='gcr.io/vpc-sc-demo-nicholascain15/vpc-sc-live-demo'
export TAG='latest'


sudo docker build -t ${IMAGE?}:${TAG?} .
sudo docker push ${IMAGE?}:${TAG?}
gcloud run deploy vpc-sc-live-demo\
  --project=vpc-sc-demo-nicholascain15\
  --platform=managed\
  --region=us-central1\
  --image=${IMAGE?}:${TAG?}\
  --allow-unauthenticated \
  --tag=${SERVICE_TAG?}