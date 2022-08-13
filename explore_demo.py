from invoke import task
import requests
import uuid
import json


WEBHOOK_PING_DATA = {"fulfillmentInfo":{"tag":"validatePhoneLine"},"sessionInfo":{"parameters":{"phone_number":"123456"}}}
WEBHOOK_TRIGGER_URI = 'https://us-central1-vpc-sc-demo-nicholascain14.cloudfunctions.net/custom-telco-webhook'
# BACKEND_SERVER_URI = 'https://demo-backend-7hkf25keba-uc.a.run.app'
BACKEND_SERVER_URI = 'http://localhost:5000'
PROJECT_ID = 'vpc-sc-demo-nicholascain14'
SERVICE_ACCOUNT_KEY_FILE = "build/keys/demo-backend"


def get_headers(c=None, key_file=None, include_json=True, token_type='identity'):
  headers = {}
  headers["x-goog-user-project"]=PROJECT_ID
  if include_json==True:
    headers['Content-type'] = 'application/json'
  if key_file:
    c.run(f'gcloud auth activate-service-account --key-file={key_file}', hide=True)
    if token_type == 'identity':
      token = c.run('gcloud auth print-identity-token', hide=True).stdout.strip()
    elif token_type == 'access':
      token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
    else:
      raise RuntimeError(f'token_type was expected to be one of ["access", "identity"], received: {token_type}')
    headers['Authorization'] = f'Bearer {token}'
  return headers


@task
def webhook_external_not_authenticated_ping(c, quiet=False):
  headers = get_headers()
  result = requests.post(WEBHOOK_TRIGGER_URI, json=WEBHOOK_PING_DATA, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def webhook_external_authenticated_ping(c, quiet=False):
  headers = get_headers(c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  result = requests.post(WEBHOOK_TRIGGER_URI, json=WEBHOOK_PING_DATA, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def webhook_internal_not_authenticated_ping(c, quiet=False):
  headers = get_headers(include_json=False)
  result = requests.get(f'{BACKEND_SERVER_URI}/ping_webhook?authenticated=false', headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def webhook_internal_authenticated_ping(c, quiet=False):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  result = requests.get(f'{BACKEND_SERVER_URI}/ping_webhook?authenticated=true', headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def agent_internal_ping(c, quiet=False):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  result = requests.get(f'{BACKEND_SERVER_URI}/ping_agent', headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def agent_external_ping(c, quiet=False):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE, token_type='access')
  result = requests.get(f'https://us-central1-dialogflow.googleapis.com/v3/projects/{PROJECT_ID}/locations/us-central1/agents', headers=headers)
  if result.status_code != 200:
    if not quiet:
      print(result.status_code, result.text)
    return result
  agent_name = {agent['displayName']:agent['name'] for agent in result.json()['agents']}['Telecommunications']
  result = requests.get(f'https://us-central1-dialogflow.googleapis.com/v3/{agent_name}/flows', headers=headers)
  if result.status_code != 200:
    if not quiet:
      print(result.status_code, result.text)
    return result
  flow_name = {flow['displayName']:flow['name'] for flow in result.json()['flows']}['Cruise Plan']
  result = requests.get(f'https://us-central1-dialogflow.googleapis.com/v3/{flow_name}/pages', headers=headers)
  if result.status_code != 200:
    if not quiet:
      print(result.status_code, result.text)
    return result
  page_name = {page['displayName']:page['name'] for page in result.json()['pages']}['Collect Customer Line']
  data = {
    'queryInput': {'languageCode': 'en', 'text': {'text': '123456'}},
    'queryParams': {'currentPage': page_name},
  }
  result = requests.post(f'https://us-central1-dialogflow.googleapis.com/v3/{agent_name}/sessions/{uuid.uuid1()}:detectIntent', json=data, headers=headers)
  if result.status_code != 200:
    if not quiet:
      print(result.status_code, result.text)
    return result
  for execution_member in result.json()['queryResult']['diagnosticInfo']['Execution Sequence']:
    for step_name, step_dict in execution_member.items():
      if 'FunctionExecution' in step_dict:
        execution_dict = step_dict['FunctionExecution']
        if 'Webhook' in execution_dict:
          if execution_dict['Webhook']['Status'] != 'OK':
            error_code = execution_dict['Webhook']['Status']['ErrorCode']
            if error_code in ['PERMISSION_DENIED', 'ERROR_OTHER']:
              error_code = 403
            if not quiet:
              print(error_code)
            response = requests.Response()
            response.status_code=error_code
            return response
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def ping_all(c):
  print(f'webhook-external-authenticated-false: {webhook_external_not_authenticated_ping(c, quiet=True).status_code}')
  print(f'webhook-external-authenticated-true:  {webhook_external_authenticated_ping(c, quiet=True).status_code}')
  print(f'webhook-internal-authenticated-false: {webhook_internal_not_authenticated_ping(c, quiet=True).status_code}')
  print(f'webhook-internal-authenticated-true:  {webhook_internal_authenticated_ping(c, quiet=True).status_code}')
  print(f'agent-internal: {agent_internal_ping(c, quiet=True).status_code}')
  print(f'agent-external: {agent_external_ping(c, quiet=True).status_code}')


@task
def webhook_update_access(c, allow_unauthenticated=True, quiet=False):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"allow_unauthenticated": allow_unauthenticated}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_webhook_access?authenticated=true', json=data, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def webhook_update_ingress(c, internal_only=True, quiet=False):
  headers = get_headers(include_json=False, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"internal_only": internal_only}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_webhook_ingress?authenticated=true', json=data, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def perimeter_update_dialogflow(c, restricted=True, quiet=False):
  headers = get_headers(include_json=True, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"api": 'dialogflow.googleapis.com', 'restricted':restricted}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_security_perimeter', json=data, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def perimeter_update_cloudfunctions(c, restricted=True, quiet=False):
  headers = get_headers(include_json=True, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"api": 'cloudfunctions.googleapis.com', 'restricted':restricted}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_security_perimeter', json=data, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def agent_update_webhook(c, fulfillment, quiet=False):
  headers = get_headers(include_json=True, c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  data = {"fulfillment": fulfillment}
  result = requests.post(f'{BACKEND_SERVER_URI}/update_agent_webhook', json=data, headers=headers)
  if not quiet:
    if result.status_code != 200:
      print(result.status_code, result.text)
    else:
      print(result.status_code)
  return result


@task
def get_status(c, 
  restricted_services=True,
  webhook_fulfillment=True,
  webhook_ingress=True,
  webhook_access=True,
  quiet=False,
):
  headers = get_headers(c=c, key_file=SERVICE_ACCOUNT_KEY_FILE)
  query_list = []
  for key, val in {
    'restricted_services':restricted_services,
    'webhook_fulfillment':webhook_fulfillment,
    'webhook_ingress':webhook_ingress,
    'webhook_access':webhook_access
  }.items():
    if val:
      query_list.append(f'{key}=true')
  query_str = f'?{"&".join(query_list)}'
  result = requests.get(f'{BACKEND_SERVER_URI}/get_status{query_str}', headers=headers)
  if not quiet:
    print(result.status_code)
    print(json.dumps(json.loads(result.text), indent=2))
  return result
