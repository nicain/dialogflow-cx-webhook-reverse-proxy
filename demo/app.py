from flask import Flask, request, Response, abort, render_template, send_from_directory, redirect, url_for
import os
import logging
import json
import requests
from base64 import b64encode
import uuid
import zipfile
import io

import python_terraform as pt
from urllib.parse import urlparse 

from google.oauth2 import id_token
from google.auth.transport import requests as reqs
import google.oauth2.credentials

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
pr_key = RSA.import_key(open('private_key.pem', 'r').read())
public_pem = open('public_key.pem', 'r').read()


PROD = os.getenv("PROD") == 'true'
app = Flask(__name__, static_folder='frontend/build')
app.logger.setLevel(logging.INFO)

with open('principal.env', 'r') as f:
  PRINCIPAL = f.read().strip()

def user_service_domain(request):
  if request.host_url in ['http://localhost:5001/', 'http://localhost:8081/']:
    assert not PROD
    domain = 'user-service.localhost'
  else:
    assert PROD
    domain = urlparse(request.host_url).hostname
  app.logger.info(f'user_service_domain(request): "{domain}"')
  return domain

def login_landing_uri(request):
  if request.host_url == 'http://localhost:5001/':
    assert not PROD
    landing_uri = 'http://user-service.localhost:3000'
  elif request.host_url == 'http://localhost:8081/':
    assert not PROD
    landing_uri = 'http://user-service.localhost:8080'
  else:
    assert PROD
    landing_uri = request.host_url
  app.logger.info(f'login_landing_uri(request): landing_uri="{landing_uri}"')
  return landing_uri



authorized_emails = [
  PRINCIPAL,
]

AUTH_SERVICE_HOSTNAME = 'authentication-service-moxl25afhq-uc.a.run.app'
AUTH_SERVICE_AUTH_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/auth'
AUTH_SERVICE_VERIFY_AUD_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/verify_aud'
AUTH_SERVICE_LOGIN_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/login'
PING_WEBHOOK_EXTERNAL_PROXY_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/ping_webhook_external_proxy'

SERVICE_DIRECTORY_NAMESPACE = 'df-namespace'
SERVICE_DIRECTORY_SERVICE = 'df-service'
DOMAIN = 'webhook.internal'

ACCESS_POLICY_NAME = 'accessPolicies/102736959981'
PERIMETER_TITLE = 'df_webhook'


import base64
from Crypto.Cipher import AES
from Crypto import Random
from google.cloud import storage


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def frontend(path):
  if path != "" and os.path.exists(app.static_folder + '/' + path):
      response = send_from_directory(app.static_folder, path)
  else:
      response = send_from_directory(app.static_folder, 'index.html')
  return response



class AESCipher:

    def __init__( self, key=None, BS=16):
        self.key = uuid.uuid4().hex.encode() if key is None else key
        self.BS = BS

    def pad(self, s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS) 

    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt( self, raw ):
        raw = self.pad(raw).encode()
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return self.unpad(cipher.decrypt( enc[16:] ))


def webhook_response_ok(response_dict):
  if response_dict.get('sessionInfo',{}).get('parameters',{}).get('domestic_coverage') != 'false':
    return False
  if response_dict.get('sessionInfo',{}).get('parameters',{}).get('phone_line_verified') != 'true':
    return False
  return True


def get_token(request, token_type='access'):

  if not request.cookies.get("session_id"):
    app.logger.info(f'get_token request did not have a session_id')
    return None

  params = {
    'session_id': request.cookies.get("session_id"),
    'origin': request.host_url,
  }
  r = requests.get(AUTH_SERVICE_AUTH_ENDPOINT, params=params)
  if r.status_code == 401:
    app.logger.info(f'  auth-service "{AUTH_SERVICE_AUTH_ENDPOINT}" rejected request: {r.text}')
    return None

  zf = zipfile.ZipFile(io.BytesIO(r.content))
  key_bytes_stream = zf.open('key').read()
  decrypt = PKCS1_OAEP.new(key=pr_key)
  decrypted_message = decrypt.decrypt(key_bytes_stream)
  aes_cipher = AESCipher(key=decrypted_message)
  auth_data = json.loads(aes_cipher.decrypt(zf.open('session_data').read()).decode())

  try:
    info = id_token.verify_oauth2_token(auth_data['id_token'], reqs.Request())
  except ValueError as e:
    if "Token expired" in str(e):
      app.logger.info(f'  auth-service token expired')
      return None
    else:
      app.logger.info(f'  auth-service ValueError: {r.text}')
      return None

  if info['email_verified'] != True:
    app.logger.info(f'  oauth error: email not verified')
    return None

  r = requests.get(AUTH_SERVICE_VERIFY_AUD_ENDPOINT, params={'aud': info['aud']})
  if r.status_code != 200 or r.json()['verified'] != True:
    app.logger.info(f'  auth-service "{AUTH_SERVICE_VERIFY_AUD_ENDPOINT}" rejected request: {r.text}')
    return None

  # if info['email'] not in authorized_emails:
  #   app.logger.info(f'  User "{info["email"]}" Not authorized')
  #   return None

  if token_type == 'access':
    return auth_data['access_token']
  elif token_type == 'identity':
    return auth_data['id_token']
  elif token_type == 'principal':
    return info['email']
  else:
    app.logger.info(f'  Requested token_type "{token_type}" not one of ["access","identity"]')
    return None


@app.route('/session', methods=['GET'])
def login():
  app.logger.info(f'/session:')
  session_id = uuid.uuid4().hex
  state = b64encode(json.dumps({'return_to': login_landing_uri(request), 'session_id':session_id, 'public_pem':public_pem}).encode()).decode()
  response = redirect(f'{AUTH_SERVICE_LOGIN_ENDPOINT}?state={state}')
  app.logger.info(f'  END /session')
  response.set_cookie("session_id", value=session_id, secure=True, httponly=True, domain=user_service_domain(request))
  response.set_cookie("user_logged_in", value='true', secure=True, httponly=False, domain=user_service_domain(request))
  return response


@app.route('/logout', methods=['GET'])
def logout():
  app.logger.info(f'/logout:')
  response = redirect(login_landing_uri(request))
  response.delete_cookie('session_id', domain=user_service_domain(request))
  response.delete_cookie('user_logged_in', domain=user_service_domain(request))
  app.logger.info(f'  END /logout')
  return response
  

def get_service_perimeter_data_uri(token, project_id):
  access_policy_id = ACCESS_POLICY_NAME.split('/')[1]
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://accesscontextmanager.googleapis.com/v1/accessPolicies/{access_policy_id}/servicePerimeters', headers=headers)
  if r.status_code != 200:
    app.logger.info(f'  accesscontextmanager API rejected request: {r.text}')
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
    else:
      response = Response(status=r.status_code, response=r.text)
      return {'response':response}

  service_perimeters = {service_perimeter['title']:service_perimeter for service_perimeter in r.json()['servicePerimeters']}
  return f'https://accesscontextmanager.googleapis.com/v1/{service_perimeters[PERIMETER_TITLE]["name"]}'



def get_service_perimeter_status(token, project_id):
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  service_perimeter_data_uri = get_service_perimeter_data_uri(token, project_id)
  if 'response' in service_perimeter_data_uri:
    return service_perimeter_data_uri
  r = requests.get(service_perimeter_data_uri, headers=headers)
  if r.status_code != 200:
    app.logger.info(f'  accesscontextmanager API rejected request: {r.text}')
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
    else:
      response = Response(status=r.status_code, response=r.text)
      return {'response':response}
  return r.json()


def get_restricted_services_status(token, project_id):
  service_perimeter_status = get_service_perimeter_status(token, project_id)
  if 'response' in service_perimeter_status:
    return service_perimeter_status
  status_dict = {}
  if 'restrictedServices' not in service_perimeter_status['status']:
    status_dict['cloudfunctions_restricted'] = False
    status_dict['dialogflow_restricted'] = False
  else:
    status_dict['cloudfunctions_restricted'] = 'cloudfunctions.googleapis.com' in service_perimeter_status['status']['restrictedServices']
    status_dict['dialogflow_restricted'] = 'dialogflow.googleapis.com' in service_perimeter_status['status']['restrictedServices']
  return status_dict
    

@app.route('/restricted_services_status_cloudfunctions', methods=['GET'])
def restricted_services_status_cloudfunctions():
  app.logger.info(f'/restricted_services_status_cloudfunctions:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  status_dict = get_restricted_services_status(token, project_id)
  if 'response' in status_dict:
    return status_dict['response']

  app.logger.info(f'  END /restricted_services_status_cloudfunctions')
  return Response(status=200, response=json.dumps({'status':status_dict['cloudfunctions_restricted']}))


@app.route('/restricted_services_status_dialogflow', methods=['GET'])
def restricted_services_status_dialogflow():
  app.logger.info(f'/restricted_services_status_dialogflow:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  status_dict = get_restricted_services_status(token, project_id)
  if 'response' in status_dict:
    return status_dict['response']

  app.logger.info(f'  END /restricted_services_status_dialogflow')
  return Response(status=200, response=json.dumps({'status':status_dict['dialogflow_restricted']}))


def get_agents(token, project_id, region):
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://{region}-dialogflow.googleapis.com/v3/projects/{project_id}/locations/{region}/agents', headers=headers)
  if r.status_code == 403:
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))
          return {'response':response}
  elif r.status_code != 200:
    app.logger.info(f'  dialogflow API rejected request: {r.text}')
    response = Response(status=r.status_code, response=r.text)
    return {'response':response}
  result_dict = r.json()
  if 'error' in result_dict:
    app.logger.info(f'  get_agents error: {r.text}')
    return None
  return {'data':{data['displayName']:data for data in result_dict['agents']}}

def get_webhooks(token, agent_name, project_id, region):
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://{region}-dialogflow.googleapis.com/v3/{agent_name}/webhooks', headers=headers)
  if r.status_code == 403:
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))
          return {'response':response}
  if r.status_code != 200:
    app.logger.info(f'  dialogflow API rejected request: {r.text}')
    response = Response(status=r.status_code, response=r.text)
    return {'response':response}
  agents = r.json()
  return {'data':{data['displayName']:data for data in agents['webhooks']}}


@app.route('/webhook_ingress_internal_only_status', methods=['GET'])
def webhook_ingress_internal_only_status():
  app.logger.info(f'/webhook_ingress_internal_only_status:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{webhook_name}', headers=headers)
  if r.status_code == 403:
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith("Permission 'cloudfunctions.functions.get' denied on resource")):
      return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))
    return Response(status=500, response=r.text)
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected request: {r.text}')
    return abort(r.status_code)
  result_dict = r.json()
  if result_dict['ingressSettings'] == 'ALLOW_INTERNAL_ONLY':
    return Response(status=200, response=json.dumps({'status':True}))
  else:
    return Response(status=200, response=json.dumps({'status':False}))


@app.route('/webhook_access_allow_unauthenticated_status', methods=['GET'])
def webhook_access_allow_unauthenticated_status():
  app.logger.info(f'/webhook_access_allow_unauthenticated_status:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v2/projects/{project_id}/locations/{region}/functions/{webhook_name}:getIamPolicy', headers=headers)
  if r.status_code == 403:
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Permission \'cloudfunctions.functions.getIamPolicy\' denied')):
      return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))
    return Response(status=500, response=r.text)
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected request: {r.text}')
    return abort(r.status_code)
  policy_dict = r.json()
  allUsers_is_invoker_member = False
  for binding in policy_dict.get('bindings', []):
    for member in binding.get('members', []):
      if member == "allUsers" and binding['role'] == "roles/cloudfunctions.invoker":
        allUsers_is_invoker_member = True
  
  app.logger.info(f'  {allUsers_is_invoker_member}')
  if allUsers_is_invoker_member:
    return Response(status=200, response=json.dumps({'status':True}))
  else:
    return Response(status=200, response=json.dumps({'status':False}))


@app.route('/update_webhook_access', methods=['POST'])
def update_webhook_access():
  app.logger.info('update_webhook_access:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  content = request.get_json(silent=True)
  internal_only = content['status']

  project_id = request.args['project_id']
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v2/projects/{project_id}/locations/{region}/functions/{webhook_name}:getIamPolicy', headers=headers)
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected getIamPolicy GET request: {r.text}')
    return abort(r.status_code)
  policy_dict = r.json()
  allUsers_is_invoker_member = False
  for binding in policy_dict.get('bindings', []):
    for member in binding.get('members', []):
      if member == "allUsers" and binding['role'] == "roles/cloudfunctions.invoker":
        allUsers_is_invoker_member = True
  if (
    (internal_only and allUsers_is_invoker_member) or 
    ((not internal_only) and (not allUsers_is_invoker_member))
  ):
    app.logger.info(f'  internal_only matches request; no change needed')
    app.logger.info(f'  internal_only ({internal_only}) matches request; no change needed')
    return Response(status=200)

  if not internal_only:
    for binding in policy_dict.get('bindings', []):
      for member in binding.get('members', []):
        if binding['role'] == "roles/cloudfunctions.invoker":
          binding['members'] = [member for member in binding['members'] if member != 'allUsers']
  else:
    if 'bindings' not in policy_dict or len(policy_dict['bindings'] == 0):
      policy_dict['bindings'] = [{'role': 'roles/cloudfunctions.invoker', 'members': []}]
    invoker_role_exists = None
    for binding in policy_dict['bindings']:
      if binding['role'] == 'roles/cloudfunctions.invoker':
        invoker_role_exists = True
        binding['members'].append('allUsers')
    if not invoker_role_exists:
      policy_dict['bindings'].append({'role': 'roles/cloudfunctions.invoker', 'members': ['allUsers']})

  r = requests.post(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{webhook_name}:setIamPolicy', headers=headers, json={'policy':policy_dict})
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected setIamPolicy POST request: {r.text}')
    return abort(r.status_code)
  return Response(status=200)


@app.route('/update_webhook_ingress', methods=['POST'])
def update_webhook_ingress():
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  content = request.get_json(silent=True)
  internal_only = content['status']
  if internal_only:
    ingress_settings = "ALLOW_INTERNAL_ONLY"
  else:
    ingress_settings = "ALLOW_ALL"
  app.logger.info(f'  internal_only: {internal_only}')

  headers = {}
  headers['Content-type'] = 'application/json'
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{webhook_name}', headers=headers)
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected GET request: {r.text}')
    return Response(status=r.status_code, response=r.text)
  webhook_data = r.json()
  if webhook_data['ingressSettings'] == ingress_settings:
    return Response(status=200)
  
  webhook_data['ingressSettings'] = ingress_settings
  r = requests.patch(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{webhook_name}', headers=headers, json=webhook_data)
  if r.status_code != 200:
    app.logger.info(f'  cloudfunctions API rejected PATCH request: {r.text}')
    return Response(status=r.status_code, response=r.text)
  return Response(status=200)


def update_service_perimeter_status_inplace(api, restrict_access, service_perimeter_status):
  if restrict_access == False:
    if 'restrictedServices' not in service_perimeter_status['status']:
      return Response(status=200)
    if api not in service_perimeter_status['status']['restrictedServices']:
      return Response(status=200)
    service_perimeter_status['status']['restrictedServices'] = [service for service in service_perimeter_status['status']['restrictedServices'] if service != api]
  else:
    if 'restrictedServices' not in service_perimeter_status['status']:
      service_perimeter_status['status']['restrictedServices'] = api
    elif api in service_perimeter_status['status']['restrictedServices']:
      return Response(status=200)
    else:
      service_perimeter_status['status']['restrictedServices'].append(api)


def update_security_perimeter(token, api, restrict_access, project_id):
  service_perimeter_status = get_service_perimeter_status(token, project_id)
  response = update_service_perimeter_status_inplace(api, restrict_access, service_perimeter_status)
  if response:
    return response
    
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  service_perimeter_data_uri = get_service_perimeter_data_uri(token, project_id)
  r = requests.patch(service_perimeter_data_uri, headers=headers, json=service_perimeter_status, params={'updateMask':'status.restrictedServices'})
  if r.status_code != 200:
    app.logger.info(f'  accesscontextmanager API rejected PATCH request: {r.text}')
    return Response(status=r.status_code, response=r.text)
  return Response(status=200)


@app.route('/update_security_perimeter_cloudfunctions', methods=['POST'])
def update_security_perimeter_cloudfunctions():
  app.logger.info('update_security_perimeter_cloudfunctions:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']

  content = request.get_json(silent=True)
  restrict_access = content['status']
  return update_security_perimeter(token, 'cloudfunctions.googleapis.com', restrict_access, project_id)


@app.route('/update_security_perimeter_dialogflow', methods=['POST'])
def update_security_perimeter_dialogflow():
  app.logger.info('update_security_perimeter_dialogflow:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']

  content = request.get_json(silent=True)
  restrict_access = content['status']
  return update_security_perimeter(token, 'dialogflow.googleapis.com', restrict_access, project_id)


@app.route('/service_directory_webhook_fulfillment_status', methods=['GET'])
def service_directory_webhook_fulfillment_status():
  app.logger.info(f'/service_directory_webhook_fulfillment_status:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = request.args['project_id']
  region = request.args['region']

  result = get_agents(token, project_id, region)
  if 'response' in result:
    return result['response']
  agent_name = result['data']['Telecommunications']['name']
  result = get_webhooks(token, agent_name, project_id, region)
  if 'response' in result:
    return result['response']
  webhook_dict = result['data']['cxPrebuiltAgentsTelecom']
  if 'serviceDirectory' in webhook_dict:
    return Response(status=200, response=json.dumps({'status':True}))
  else:
    return Response(status=200, response=json.dumps({'status':False}))


@app.route('/update_service_directory_webhook_fulfillment', methods=['POST'])
def update_service_directory_webhook_fulfillment():
  app.logger.info(f'/update_service_directory_webhook_fulfillment:')
  token = get_token(request)
  if not token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))
  content = request.get_json(silent=True)
  if content['status'] == True:
    fulfillment = 'service-directory'
  else:
    fulfillment = 'generic-web-service'

  project_id = request.args['project_id']
  region = request.args['region']
  webhook_name = request.args['webhook_name']
  
  webhook_trigger_uri = f'https://{region}-{project_id}.cloudfunctions.net/{webhook_name}'
  headers = {}
  headers['Content-type'] = 'application/json'
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  result = get_agents(token, project_id, region)
  if 'response' in result:
    return result['response']
  agent_name = result['data']['Telecommunications']['name']
  result = get_webhooks(token, agent_name, project_id, region)
  if 'response' in result:
    return result['response']
  webhook_dict = result['data']['cxPrebuiltAgentsTelecom']
  webhook_name = webhook_dict['name']
  if fulfillment=='generic-web-service':
    data = {"displayName": "cxPrebuiltAgentsTelecom", "genericWebService": {"uri": webhook_trigger_uri}}
  elif fulfillment=='service-directory':
    def b64Encode(msg_bytes):
      base64_bytes = base64.b64encode(msg_bytes)
      return base64_bytes.decode('ascii')
    credentials = google.oauth2.credentials.Credentials(token)  
    BUCKET = storage.Client(project=project_id, credentials=credentials).bucket(project_id)
    blob = storage.blob.Blob(f'ssl/server.der', BUCKET)
    allowed_ca_cert = blob.download_as_string()
    data = {
      "displayName": "cxPrebuiltAgentsTelecom", 
      "serviceDirectory": {
        "service": f'projects/{project_id}/locations/{region}/namespaces/{SERVICE_DIRECTORY_NAMESPACE}/services/{SERVICE_DIRECTORY_SERVICE}',
        "genericWebService": {
          "uri": f'https://{DOMAIN}',
          "allowedCaCerts": [b64Encode(allowed_ca_cert)]
        }
      }
    }
  else:
    return Response(status=500, response=f'Unexpected setting for fulfillment: {fulfillment}')
  r = requests.patch(f'https://{region}-dialogflow.googleapis.com/v3/{webhook_name}', headers=headers, json=data)
  if r.status_code != 200:
    app.logger.info(f'  dialogflow API unexpectedly rejected invocation POST request: {r.text}')
    return abort(r.status_code)
  
  return Response(status=200)


@app.route('/get_principal', methods=['GET'])
def get_principal():
  principal = get_token(request, token_type='principal')
  return Response(status=200, response=json.dumps({'principal': principal}))
  




@app.route('/dev', methods=['GET'])
def dev():
  access_token = get_token(request, token_type='access')
  if not access_token:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_TOKEN'}))

  project_id = "vpc-sc-demo-nicholascain15"
  webhook_name = "custom-telco-webhook"
  region = "us-central1"
  # project_id = request.args['project_id']
  # region = request.args['region']
  # webhook_name = request.args['webhook_name']

  variables = {
    'project_id':project_id,
    'access_token':access_token,
    'region': region,
    'bucket': project_id,
    'webhook_name': webhook_name,
  }
  tf = pt.Terraform(working_dir='/app/terraform')
  tf.init()
  return_code, stdout, stderr = tf.plan(out="plan.out", variables=variables, refresh=False)
  if return_code not in [0,2]:
    response = f'({return_code}) Terraform Plan Failure:\n  stdoud: {stdout}\n  stderr: {stderr}'
    app.logger.error(response)
    if "Changes to Outputs:" in stdout:
      app.logger.error("Old state detected. Destroying and re-applying...")
      return_code, stdout, stderr = tf.apply("plan.out", skip_plan=True, var=None, destroy=True)
      if return_code != 0:
        response = f'({return_code}) Terraform Destroy Failure:\n  stdoud: {stdout}\n  stderr: {stderr}'
        app.logger.error(response)
        return Response(status=500, response=response)
      return_code, stdout, stderr = tf.plan(out="plan.out", variables=variables)
      if return_code not in [0,2]:
        response = f'({return_code}) Terraform Plan Failure:\n  stdoud: {stdout}\n  stderr: {stderr}'
        app.logger.error(response)
        return Response(status=500, response=response)
    else:
      return Response(status=500, response=response)

  return_code, stdout, stderr = tf.apply("plan.out", skip_plan=True, var=None)
  if return_code != 0:
    response = f'({return_code}) Terraform Apply Failure:\n  stdoud: {stdout}\n  stderr: {stderr}'
    app.logger.error(response)
    return Response(status=500, response=response)
  
  app.logger.info('Terraform plan deployed.')
  return Response(status=200, response='OK')
# Error: Error acquiring the state lock


  '''
  terraform init && terraform apply --auto-approve \
    -var access_token=$(gcloud auth print-access-token) \
    -var project_id=${PROJECT_ID?} \
    -var vpc_network=${VPC_NETWORK} \
    -var vpc_subnetwork=${VPC_SUBNETWORK} \
    -var reverse_proxy_server_ip=${REVERSE_PROXY_SERVER_IP} \
    -var region=${REGION?}

  terraform init && terraform apply --auto-approve \
    -var service_directory_namespace=${SERVICE_DIRECTORY_NAMESPACE?} \
    -var service_directory_service=${SERVICE_DIRECTORY_SERVICE?} \
    -var service_directory_endpoint=${SERVICE_DIRECTORY_ENDPOINT?} \
    -var reverse_proxy_server_ip=${REVERSE_PROXY_SERVER_IP} \
    -var vpc_network=${VPC_NETWORK} \
    -var project_id=${PROJECT_ID?} \
    -var access_token=$(gcloud auth print-access-token) \
    -var region=${REGION?}

  terraform import \
    -var service_directory_namespace=${SERVICE_DIRECTORY_NAMESPACE?} \
    -var service_directory_service=${SERVICE_DIRECTORY_SERVICE?} \
    -var service_directory_endpoint=${SERVICE_DIRECTORY_ENDPOINT?} \
    -var reverse_proxy_server_ip=${REVERSE_PROXY_SERVER_IP} \
    -var vpc_network=${VPC_NETWORK} \
    -var project_id=${PROJECT_ID?} \
    -var access_token=$(gcloud auth print-access-token) \
    -var region=${REGION?} google_service_directory_namespace.reverse_proxy projects/vpc-sc-demo-nicholascain15/locations/us-central1/namespaces/df-namespace

  terraform import \
    -var service_directory_namespace=${SERVICE_DIRECTORY_NAMESPACE?} \
    -var service_directory_service=${SERVICE_DIRECTORY_SERVICE?} \
    -var service_directory_endpoint=${SERVICE_DIRECTORY_ENDPOINT?} \
    -var reverse_proxy_server_ip=${REVERSE_PROXY_SERVER_IP} \
    -var vpc_network=${VPC_NETWORK} \
    -var project_id=${PROJECT_ID?} \
    -var access_token=$(gcloud auth print-access-token) \
    -var region=${REGION?} google_service_directory_service.reverse_proxy projects/vpc-sc-demo-nicholascain15/locations/us-central1/namespaces/df-namespace/services/df-service

  terraform import \
    -var service_directory_namespace=${SERVICE_DIRECTORY_NAMESPACE?} \
    -var service_directory_service=${SERVICE_DIRECTORY_SERVICE?} \
    -var service_directory_endpoint=${SERVICE_DIRECTORY_ENDPOINT?} \
    -var reverse_proxy_server_ip=${REVERSE_PROXY_SERVER_IP} \
    -var vpc_network=${VPC_NETWORK} \
    -var project_id=${PROJECT_ID?} \
    -var access_token=$(gcloud auth print-access-token) \
    -var region=${REGION?} google_compute_network.vpc_network projects/vpc-sc-demo-nicholascain15/global/networks/webhook-net

  import google_compute_network.vpc_network projects/vpc-sc-demo-nicholascain15/global/networks/webhook-net


  terraform init && terraform apply --auto-approve \
    -var access_token=$(gcloud auth print-access-token) \
    -var project_id=${PROJECT_ID?} \
    -var region=${REGION?} \
    -var bucket=${PROJECT_ID?}-tf \
    -var webhook_name=${WEBHOOK_NAME?} \

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

  export AGENT_NAME=$(curl -s -X GET -H "Authorization: Bearer $(gcloud auth print-access-token)" \
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
  '''