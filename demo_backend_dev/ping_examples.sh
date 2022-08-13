
export SERVER='localhost:5000'



# curl -X POST \
#   -H "Content-Type:application/json" \
#   -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
#   -d '{"allow_unauthenticated":false, "ingress_settings":"internal-only"}' \
#   ${SERVER?}/update_webhook


# Test the webhook directly, not authenticated:
echo "External not authenticated: " $(\
curl -s -i -X POST \
  -H "Content-Type:application/json" \
  --data \
  '{
    "fulfillmentInfo":{
      "tag":"validatePhoneLine"
    },
    "sessionInfo":{
      "parameters":{
        "phone_number":"123456"
      }
    }
  }' \
  https://us-central1-vpc-sc-demo-nicholascain14.cloudfunctions.net/custom-telco-webhook | grep "^HTTP\/")


# Test the webhook directly, authenticated:
echo "External authenticated: " $(\
curl -s -i -X POST \
  -H "Content-Type:application/json" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  --data \
  '{
    "fulfillmentInfo":{
      "tag":"validatePhoneLine"
    },
    "sessionInfo":{
      "parameters":{
        "phone_number":"123456"
      }
    }
  }' \
  https://us-central1-vpc-sc-demo-nicholascain14.cloudfunctions.net/custom-telco-webhook | grep "^HTTP\/")

# Test the webhook within, not authenticated:
echo "Internal not authenticated: " $(\
curl -s -i -X GET \
  "${SERVER?}/ping_webhook?authenticated=false" | grep "^HTTP\/")

# Test the webhook within GCP, authenticated:
echo "Internal authenticated: " $(\
curl -s -i -X GET \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "${SERVER?}/ping_webhook?authenticated=true" | grep "^HTTP\/")