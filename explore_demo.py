from invoke import task
import requests

WEBHOOK_PING_DATA = {"fulfillmentInfo":{"tag":"validatePhoneLine"},"sessionInfo":{"parameters":{"phone_number":"123456"}}}
WEBHOOK_TRIGGER_URI = 'https://us-central1-vpc-sc-demo-nicholascain14.cloudfunctions.net/custom-telco-webhook'
# BACKEND_SERVER_URI = 'https://demo-backend-7hkf25keba-uc.a.run.app'
BACKEND_SERVER_URI = 'http://localhost:5000'

SERVICE_ACCOUNT_KEY_FILE = "build/keys/demo-backend"


def get_headers(c=None, key_file=None, include_json=True):
  headers = {}
  if include_json==True:
    headers['Content-type'] = 'application/json'
  if key_file:
    c.run(f'gcloud auth activate-service-account --key-file={key_file}', hide=True)
    token = c.run('gcloud auth print-identity-token', hide=True).stdout.strip()
    headers['Authorization'] = f'Bearer {token}'
  return headers


@task
def webhook_external_not_authenticated_ping(c):
  headers = get_headers()
  result = requests.post(WEBHOOK_TRIGGER_URI, json=WEBHOOK_PING_DATA, headers=headers)
  print(result.status_code)


@task
def webhook_external_authenticated_ping(c):
  headers = get_headers(c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  result = requests.post(WEBHOOK_TRIGGER_URI, json=WEBHOOK_PING_DATA, headers=headers)
  print(result.status_code)


@task
def webhook_internal_not_authenticated_ping(c):
  headers = get_headers(include_json=False)
  result = requests.get(f'{BACKEND_SERVER_URI}/ping_webhook?authenticated=false', headers=headers)
  print(result.status_code)


@task
def webhook_internal_authenticated_ping(c):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  result = requests.get(f'{BACKEND_SERVER_URI}/ping_webhook?authenticated=true', headers=headers)
  print(result.status_code)


@task
def webhook_update_access(c, allow_unauthenticated=True):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"allow_unauthenticated": allow_unauthenticated}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_webhook_access?authenticated=true', json=data, headers=headers)
  print(result.status_code)
