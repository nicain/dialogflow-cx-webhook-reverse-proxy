from urllib import response
from flask import Flask, request, Response, abort, render_template, send_from_directory, redirect, url_for
import os
import logging
import json
import requests
from base64 import b64encode
import uuid
import zipfile
import io
import tempfile
import tasks
from invoke import context
import collections


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


def user_service_domain(request):
  if request.host_url in ['http://localhost:5001/', 'http://localhost:8081/']:
    assert not PROD
    domain = 'user-service.localhost'
  else:
    assert PROD
    domain = urlparse(request.host_url).hostname
  app.logger.info(f'user_service_domain(request): "{domain}"')
  return domain

def login_landing_uri(request, query_params={}):
  if request.host_url == 'http://localhost:5001/':
    assert not PROD
    landing_uri = 'http://user-service.localhost:3000'
  elif request.host_url == 'http://localhost:8081/':
    assert not PROD
    landing_uri = 'http://user-service.localhost:8080'
  else:
    assert PROD
    landing_uri = request.host_url

  if landing_uri[-1] == '/':
    landing_uri = landing_uri[:-1]

  if query_params:
    param_string = '&'.join([f'{key}={val}'for key, val in query_params.items()])
    landing_uri = f'{landing_uri}/?{param_string}'


  app.logger.info(f'login_landing_uri(request): landing_uri="{landing_uri}"')
  return landing_uri

AUTH_SERVICE_HOSTNAME = 'auth.dialogflow-demo.app'
# AUTH_SERVICE_HOSTNAME = 'authentication-service-moxl25afhq-uc.a.run.app'
AUTH_SERVICE_AUTH_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/auth'
# AUTH_SERVICE_VERIFY_AUD_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/verify_aud'
AUTH_SERVICE_LOGIN_ENDPOINT = f'http://{AUTH_SERVICE_HOSTNAME}/login'

DOMAIN = 'webhook.internal'
ACCESS_POLICY_RESOURCE = 'module.service_perimeter.google_access_context_manager_access_policy.access_policy[0]'


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


 
class LRU:
 
  def __init__(self, func, maxsize=128):
    self.cache = collections.OrderedDict()
    self.func = func
    self.maxsize = maxsize

  def __call__(self, *args):
    cache = self.cache
    if args in cache:
      cache.move_to_end(args)
      return cache[args]
    result = self.func(*args)
    cache[args] = result
    if len(cache) > self.maxsize:
      cache.popitem(last=False)
    return result


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

def get_token_from_auth_server(session_id, origin):

  params = {
    'session_id': session_id,
    'origin': origin,
  }

  r = requests.get(AUTH_SERVICE_AUTH_ENDPOINT, params=params)
  if r.status_code == 401:
    app.logger.info(f'  auth-service "{AUTH_SERVICE_AUTH_ENDPOINT}" rejected request: {r.text}')
    return {'response': Response(status=500, response=json.dumps({'status':'BLOCKED', 'reason':'REJECTED_REQUEST'}))}

  zf = zipfile.ZipFile(io.BytesIO(r.content))
  key_bytes_stream = zf.open('key').read()
  decrypt = PKCS1_OAEP.new(key=pr_key)
  decrypted_message = decrypt.decrypt(key_bytes_stream)
  aes_cipher = AESCipher(key=decrypted_message)
  auth_data = json.loads(aes_cipher.decrypt(zf.open('session_data').read()).decode())

  return {'auth_data': auth_data}


def get_token(request, token_type='access', cache=LRU(get_token_from_auth_server) ):

  if not request.cookies.get("session_id"):
    app.logger.info(f'get_token request did not have a session_id')
    return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'BAD_SESSION_ID'}))}

  session_id = request.cookies.get("session_id")
  origin = request.host_url

  response = cache(session_id, origin)
  if 'response' in response:
    cache.cache.pop((session_id, origin))
    return response
  auth_data = response['auth_data']

  try:
    info = id_token.verify_oauth2_token(auth_data['id_token'], reqs.Request())
  except ValueError as e:
    if "Token expired" in str(e):
      app.logger.info(f'  auth-service token expired')
      return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'TOKEN_EXPIRED'}))}
    else:
      response = f'  auth-service ValueError: {r.text}'
      app.logger.info(response)
      return {'response': Response(status=500, response=json.dumps({'status':'BLOCKED', 'reason':response.lstrip()}))}

  if info['email_verified'] != True:
    app.logger.info(f'  oauth error: email not verified')
    return {'response': Response(status=500, response=json.dumps({'status':'BLOCKED', 'reason':'BAD_EMAIL'}))}

  # r = requests.get(AUTH_SERVICE_VERIFY_AUD_ENDPOINT, params={'aud': info['aud']})
  # if r.status_code != 200 or r.json()['verified'] != True:
  #   response = f'  auth-service "{AUTH_SERVICE_VERIFY_AUD_ENDPOINT}" rejected request: {r.text}'
  #   app.logger.info(response)
  #   return {'response': Response(status=500, response=json.dumps({'status':'BLOCKED', 'reason':response.lstrip()}))}

  response = {}
  if token_type == 'access_token':
    response['access_token'] = auth_data['access_token']
  elif token_type == 'id_token':
    response['id_token'] = auth_data['id_token']
  elif token_type == 'email':
    response['email'] = auth_data['email']
  else:
    response = f'  Requested token_type "{token_type}" not one of ["access_token","id_token","email"]'
    app.logger.info(response)
    return {'response': Response(status=500, response=json.dumps({'status':'BLOCKED', 'reason':response.lstrip()}))}
  return response


@app.route('/session', methods=['GET'])
def login():
  app.logger.info(f'/session:')
  session_id = uuid.uuid4().hex
  state = b64encode(json.dumps({'return_to': login_landing_uri(request, query_params=request.args), 'session_id':session_id, 'public_pem':public_pem}).encode()).decode()
  response = redirect(f'{AUTH_SERVICE_LOGIN_ENDPOINT}?state={state}')
  app.logger.info(f'  END /session')
  response.set_cookie("session_id", value=session_id, secure=True, httponly=True, domain=user_service_domain(request))
  response.set_cookie("user_logged_in", value='true', secure=True, httponly=False, domain=user_service_domain(request))
  return response


@app.route('/logout', methods=['GET'])
def logout():
  app.logger.info(f'/logout:')
  response = redirect(login_landing_uri(request, query_params=request.args))
  response.delete_cookie('session_id', domain=user_service_domain(request))
  response.delete_cookie('user_logged_in', domain=user_service_domain(request))
  app.logger.info(f'  END /logout')
  return response
  

def get_service_perimeter_data_uri(token, project_id, access_policy_name):
  perimeter_title = 'df_webhook'
  access_policy_id = access_policy_name.split('/')[1]
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://accesscontextmanager.googleapis.com/v1/accessPolicies/{access_policy_id}/servicePerimeters', headers=headers)
  if r.status_code != 200:
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Access Context Manager API has not been used in project')):
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'ACCESS_CONTEXT_MANAGER_API_DISABLED'}))
      return {'response':response}
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
    else:
      app.logger.info(f'  accesscontextmanager API rejected request: {r.text}')
      response = Response(status=500, response=r.text)
      return {'response':response}

  for service_perimeter_dict in r.json().get('servicePerimeters', []):
    if service_perimeter_dict['title'] == perimeter_title:
      return {'uri': f'https://accesscontextmanager.googleapis.com/v1/{service_perimeter_dict["name"]}'}
  
  return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERIMETER_NOT_FOUND'}))}


def get_service_perimeter_status(token, project_id, access_policy_name):
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  response = get_service_perimeter_data_uri(token, project_id, access_policy_name)
  if 'response' in response:
    return response
  service_perimeter_data_uri = response['uri']
  r = requests.get(service_perimeter_data_uri, headers=headers)
  if r.status_code != 200:
    app.logger.info(f'  accesscontextmanager API rejected request: {r.text}')
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Access Context Manager API has not been used in project')):
      return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'ACCESS_CONTEXT_MANAGER_API_DISABLED'}))
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
    else:
      response = Response(status=r.status_code, response=r.text)
      return {'response':response}
  return r.json()


def get_restricted_services_status(token, project_id, access_policy_name):
  service_perimeter_status = get_service_perimeter_status(token, project_id, access_policy_name)
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


def get_project_number(token, project_id):

  headers = {}
  headers['Content-type'] = 'application/json'
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}', headers=headers)
  if 'projectNumber' in r.json():
    return {'project_number':r.json()['projectNumber']}
  else:
    return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT'}))}


def get_access_policy_name(token, access_policy_title, project_id):

  if not access_policy_title:
    return {"response": Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_ACCESS_POLICY'}))}

  headers = {}
  headers['Content-type'] = 'application/json'
  headers['Authorization'] = f'Bearer {token}'
  r = requests.post(f'https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getAncestry', headers=headers)
  if r.status_code != 200:
      return {"response": Response(status=500, response=r.text)}
  
  organization_id = None
  for ancestor_dict in r.json().get('ancestor', []):
    if ancestor_dict["resourceId"]["type"] == 'organization':
      organization_id = ancestor_dict["resourceId"]["id"]
  if not organization_id:
    return {"response": Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_ORGANIZATION'}))}

  response = get_project_number(token, project_id)
  if 'response' in response:
    return response['response']
  project_number = response['project_number']

  headers = {}
  headers['Content-type'] = 'application/json'
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations/{organization_id}', headers=headers)

  for policy in r.json().get('accessPolicies', []):
    if policy['title'] == access_policy_title:
      if f'projects/{project_number}' in policy['scopes']:
        return {"access_policy_name": policy['name']}
      # else:
      #   return {"response": Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PROJECT_NOT_IN_POLICY_SCOPE'}))}

  return {"response": Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'POLICY_NOT_FOUND'}))}


@app.route('/restricted_services_status_cloudfunctions', methods=['GET'])
def restricted_services_status_cloudfunctions():
  app.logger.info(f'/restricted_services_status_cloudfunctions:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  access_policy_title = request.args.get('access_policy_title', None)

  response = get_access_policy_name(token, access_policy_title, project_id)
  if 'response' in response:
    return response['response']
  access_policy_name = response['access_policy_name']
  status_dict = get_restricted_services_status(token, project_id, access_policy_name)
  if 'response' in status_dict:
    return status_dict['response']

  app.logger.info(f'  END /restricted_services_status_cloudfunctions')
  return Response(status=200, response=json.dumps({'status':status_dict['cloudfunctions_restricted']}))


@app.route('/restricted_services_status_dialogflow', methods=['GET'])
def restricted_services_status_dialogflow():
  app.logger.info(f'/restricted_services_status_dialogflow:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  access_policy_title = request.args.get('access_policy_title', None)

  response = get_access_policy_name(token, access_policy_title, project_id)
  if 'response' in response:
    return response['response']
  access_policy_name = response['access_policy_name']
  status_dict = get_restricted_services_status(token, project_id, access_policy_name)
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
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Dialogflow API has not been used in project')):
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'DIALOGFLOW_API_DISABLED'}))
      return {'response':response}
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Caller does not have required permission')):
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'WRONG_PERMISSION'}))
      return {'response':response}
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          return {"response": Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))}
    if r.json()['error']['status'] == 'PERMISSION_DENIED':
      response = Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
      return {'response':response}
  elif r.status_code != 200:
    app.logger.info(f'  dialogflow API rejected request: {r.text}')
    response = Response(status=r.status_code, response=r.text)
    return {'response':response}
  result_dict = r.json()
  if len(result_dict) == 0:
    return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'AGENT_NOT_FOUND'}))}
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


def check_function_exists(token, project_id, region, function_name):

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{function_name}', headers=headers)
  if r.status_code == 200:
    return {'status': 'OK'}
  elif r.status_code == 404 and r.json()['error']['status']=='NOT_FOUND':
    return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'WEBHOOK_NOT_FOUND'}))}
  elif r.status_code == 403 and r.json()['error']['message'].startswith('Cloud Functions API has not been used in project'):
    return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'CLOUDFUNCTIONS_API_DISABLED'}))}
  elif r.status_code == 403:
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith("Permission 'cloudfunctions.functions.get' denied on resource")):
      return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))}
    for details in r.json()['error']['details']:
      for violation in details['violations']:
        if violation['type'] == 'VPC_SERVICE_CONTROLS':
          return {'response': Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'VPC_SERVICE_CONTROLS'}))}
    return {'response': Response(status=500, response=r.text)}
  else:
    return {'response': Response(status=500, response=json.dumps(r.json()))}

@app.route('/webhook_ingress_internal_only_status', methods=['GET'])
def webhook_ingress_internal_only_status():
  app.logger.info(f'/webhook_ingress_internal_only_status:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  response = check_function_exists(token, project_id, region, webhook_name)
  if 'response' in response:
    return response['response']

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v1/projects/{project_id}/locations/{region}/functions/{webhook_name}', headers=headers)
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
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  region = request.args['region']
  webhook_name = request.args['webhook_name']

  response = check_function_exists(token, project_id, region, webhook_name)
  if 'response' in response:
    return response['response']

  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://cloudfunctions.googleapis.com/v2/projects/{project_id}/locations/{region}/functions/{webhook_name}:getIamPolicy', headers=headers)
  if r.status_code == 403:
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Permission \'cloudfunctions.functions.getIamPolicy\' denied')):
      return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'PERMISSION_DENIED'}))
    if (r.json()['error']['status'] == 'PERMISSION_DENIED') and (r.json()['error']['message'].startswith('Cloud Functions API has not been used in project')):
      return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'CLOUDFUNCTIONS_API_DISABLED'}))
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
  
  app.logger.info(f'  allUsers_is_invoker_member: {allUsers_is_invoker_member}')
  if allUsers_is_invoker_member:
    return Response(status=200, response=json.dumps({'status':False}))
  else:
    return Response(status=200, response=json.dumps({'status':True}))


@app.route('/update_webhook_access', methods=['POST'])
def update_webhook_access():
  app.logger.info('update_webhook_access:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  content = request.get_json(silent=True)
  internal_only = content['status']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
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
    (not internal_only and allUsers_is_invoker_member) or 
    ((internal_only) and (not allUsers_is_invoker_member))
  ):
    app.logger.info(f'  internal_only matches request; no change needed')
    app.logger.info(f'  internal_only ({internal_only}) matches request; no change needed')
    return Response(status=200)

  if internal_only:
    for binding in policy_dict.get('bindings', []):
      for member in binding.get('members', []):
        if binding['role'] == "roles/cloudfunctions.invoker":
          binding['members'] = [member for member in binding['members'] if member != 'allUsers']
  else:
    if 'bindings' not in policy_dict or len(policy_dict['bindings']) == 0:
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
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
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


def update_security_perimeter(token, api, restrict_access, project_id, access_policy_name):
  service_perimeter_status = get_service_perimeter_status(token, project_id, access_policy_name)
  response = update_service_perimeter_status_inplace(api, restrict_access, service_perimeter_status)
  if response:
    return response
    
  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  response = get_service_perimeter_data_uri(token, project_id, access_policy_name)
  if 'response' in response:
    return response
  service_perimeter_data_uri = response['uri']
  r = requests.patch(service_perimeter_data_uri, headers=headers, json=service_perimeter_status, params={'updateMask':'status.restrictedServices'})
  if r.status_code != 200:
    app.logger.info(f'  accesscontextmanager API rejected PATCH request: {r.text}')
    return Response(status=r.status_code, response=r.text)
  return Response(status=200)


@app.route('/update_security_perimeter_cloudfunctions', methods=['POST'])
def update_security_perimeter_cloudfunctions():
  app.logger.info('update_security_perimeter_cloudfunctions:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  access_policy_title = request.args['access_policy_title']
  response = get_access_policy_name(token, access_policy_title, project_id)
  if 'response' in response:
    return response['response']
  access_policy_name = response['access_policy_name']

  content = request.get_json(silent=True)
  restrict_access = content['status']
  return update_security_perimeter(token, 'cloudfunctions.googleapis.com', restrict_access, project_id, access_policy_name)


@app.route('/update_security_perimeter_dialogflow', methods=['POST'])
def update_security_perimeter_dialogflow():
  app.logger.info('update_security_perimeter_dialogflow:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  access_policy_title = request.args['access_policy_title']
  response = get_access_policy_name(token, access_policy_title, project_id)
  if 'response' in response:
    return response['response']
  access_policy_name = response['access_policy_name']

  content = request.get_json(silent=True)
  restrict_access = content['status']
  return update_security_perimeter(token, 'dialogflow.googleapis.com', restrict_access, project_id, access_policy_name)


@app.route('/service_directory_webhook_fulfillment_status', methods=['GET'])
def service_directory_webhook_fulfillment_status():
  app.logger.info(f'/service_directory_webhook_fulfillment_status:')
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  region = request.args['region']

  result = get_agents(token, project_id, region)
  if 'response' in result:
    return result['response']
  if 'Telecommunications' not in result['data']:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'AGENT_NOT_FOUND'})) 
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
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  token = token_dict['access_token']

  content = request.get_json(silent=True)
  if content['status'] == True:
    fulfillment = 'service-directory'
  else:
    fulfillment = 'generic-web-service'

  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':'BLOCKED', 'reason':'NO_PROJECT_ID'})) 
  bucket = request.args['bucket']
  region = request.args['region']
  webhook_name = request.args['webhook_name']
  service_directory_namespace = "df-namespace"
  service_directory_service = "df-service"
  webhook_trigger_uri = f'https://{region}-{project_id}.cloudfunctions.net/{webhook_name}'

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
    BUCKET = storage.Client(project=project_id, credentials=credentials).bucket(bucket)
    blob = storage.blob.Blob(f'server.der', BUCKET)
    allowed_ca_cert = blob.download_as_string()
    data = {
      "displayName": "cxPrebuiltAgentsTelecom", 
      "serviceDirectory": {
        "service": f'projects/{project_id}/locations/{region}/namespaces/{service_directory_namespace}/services/{service_directory_service}',
        "genericWebService": {
          "uri": f'https://{DOMAIN}',
          "allowedCaCerts": [b64Encode(allowed_ca_cert)]
        }
      }
    }
  else:
    return Response(status=500, response=f'Unexpected setting for fulfillment: {fulfillment}')


  headers = {}
  headers["x-goog-user-project"] = project_id
  headers['Authorization'] = f'Bearer {token}'
  r = requests.patch(f'https://{region}-dialogflow.googleapis.com/v3/{webhook_name}', headers=headers, json=data)
  if r.status_code != 200:
    app.logger.info(f'  dialogflow API unexpectedly rejected invocation POST request: {r.text}')
    return abort(r.status_code)
  
  return Response(status=200)


@app.route('/get_principal', methods=['GET'])
def get_principal():
  token_dict = get_token(request, token_type='email')
  if 'response' in token_dict:
    return token_dict['response']
  return Response(status=200, response=json.dumps({'principal': token_dict['email']}))
  

@app.route('/validate_project_id', methods=['get'])
def validate_project_id():
  project_id = request.args.get('project_id', None)
  if not project_id:
    return Response(status=200, response=json.dumps({'status':False}, indent=2))
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    print("ERROR TO DEBUG", token_dict['response'])
    return token_dict['response']
  access_token = token_dict['access_token']

  headers = {}
  headers['Authorization'] = f'Bearer {access_token}'
  r = requests.get(f'https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}', headers=headers)

  if r.status_code == 200:
    return Response(status=200, response=json.dumps({'status':True}, indent=2))
  else:
    return Response(status=200, response=json.dumps({'status':False}, indent=2))








def get_terraform_env(access_token, request_args, debug=False):
  env = {}
  env["GOOGLE_OAUTH_ACCESS_TOKEN"] = access_token
  env["TF_VAR_project_id"] = request_args["project_id"]
  env["TF_VAR_bucket"] = request_args["bucket"]
  env["TF_VAR_region"] = request_args["region"]
  if "access_policy_title" in request_args:
    env["TF_VAR_access_policy_title"] = request_args["access_policy_title"]
  else:
    env["TF_VAR_access_policy_title"] = 'null'
  # if debug:
  #   env["TF_LOG"] = "DEBUG"
  return env


def get_access_policy_title(token, access_policy_id):
  headers = {}
  headers['Authorization'] = f'Bearer {token}'
  r = requests.get(f'https://accesscontextmanager.googleapis.com/v1/accessPolicies/{access_policy_id}', headers=headers)
  if r.status_code != 200:
    return {'response': Response(status=500, response=r.text)}
  return {'access_policy_title': r.json()['title']}



@app.route('/asset_status', methods=['GET'])
def asset_status():
  debug = request.args.get('debug') == 'true'
  target = request.args.get('target', None)
  update = request.args.get('update', True)
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  access_token = token_dict['access_token']
  env = get_terraform_env(access_token, request.args, debug=debug)

  c = context.Context()
  module = '/app/deploy/terraform/main.tf'
  prefix = f'terraform/{request.args["project_id"]}'
  with tempfile.TemporaryDirectory() as workdir:

    result = tasks.tf_init(c, module, workdir, env, prefix, debug)
    if result: return result

    resource_id_dict = {}
    if update:
      result = tasks.tf_plan(c, module, workdir, env, debug, target=target)
      if result is not None:
        if 'response' in result: return result['response']
        for hook in result['hooks']['refresh_complete']:
          if 'id_value' in hook:
            resource_id_dict[hook['resource']['addr']] = hook['id_value']

    if ACCESS_POLICY_RESOURCE in resource_id_dict:
      access_policy_id = resource_id_dict[ACCESS_POLICY_RESOURCE]
      response = get_access_policy_title(access_token, access_policy_id)
      if 'response' in response: return response['response']
      access_policy_title = response['access_policy_title']
    else:
      access_policy_title = None

    result = tasks.tf_state_list(c, module, workdir, env, debug)
    if 'response' in result: return result["response"]
    resources = result['resources']
        
    return Response(status=200, response=json.dumps(
      {
        'status':'OK', 
        'resources':resources, 
        'resource_id_dict':resource_id_dict,
        'accessPolicyTitle': access_policy_title,
      }, indent=2)
    )


@app.route('/update_target', methods=['POST'])
def update_target():
  content = request.get_json(silent=True)
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  access_token = token_dict['access_token']

  debug = request.args.get('debug') == 'true'
  env = get_terraform_env(access_token, request.args, debug=debug)
  targets = content.get('targets')
  destroy = content['destroy']

  if targets == ["all"]:
    targets = None

  c = context.Context()
  module = '/app/deploy/terraform/main.tf'
  prefix = f'terraform/{request.args["project_id"]}'
  with tempfile.TemporaryDirectory() as workdir:

    result = tasks.tf_init(c, module, workdir, env, prefix, debug)
    if result: return result

    if targets:
      for target in targets:
        result = tasks.tf_plan(c, module, workdir, env, debug, target=target)
        if result and 'response' in result: return result['response']
        result = tasks.tf_apply(c, module, workdir, env, debug, destroy, target=target)
    else:
        result = tasks.tf_plan(c, module, workdir, env, debug)
        result = tasks.tf_apply(c, module, workdir, env, debug, destroy)
    if result: return result

    result = tasks.tf_state_list(c, module, workdir, env, debug)
    if 'response' in result: return result["response"]
    resources = result['resources']

    for resource in sorted(resources):
      print(resource)
        
    return Response(status=200, response=json.dumps({'status':'OK', 'resources':resources}, indent=2))


@app.route('/unlock', methods=['post'])
def unlock():
  debug = request.args.get('debug') == 'true'
  content = request.get_json(silent=True)
  lock_id = content['lock_id']
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  access_token = token_dict['access_token']
  env = get_terraform_env(access_token, request.args)

  c = context.Context()
  module = '/app/deploy/terraform/main.tf'
  prefix = f'terraform/{request.args["project_id"]}'
  with tempfile.TemporaryDirectory() as workdir:

    result = tasks.tf_init(c, module, workdir, env, prefix, debug)
    if result: return result

    result = tasks.tf_unlock(c, module, workdir, env, debug, lock_id)
    if result: return result

  return Response(status=200, response=json.dumps({'status':'OK'}, indent=2))


@app.route('/import', methods=['post'])
def import_resource():
  target = request.args['target']
  debug = request.args.get('debug', True)
  content = request.get_json(silent=True)
  resource_raw = content['resourceName']
  resource = resource_raw.split('\'')[1]
  token_dict = get_token(request, token_type='access_token')
  if 'response' in token_dict:
    return token_dict['response']
  access_token = token_dict['access_token']
  env = get_terraform_env(access_token, request.args)

  c = context.Context()
  module = '/app/deploy/terraform/main.tf'
  prefix = f'terraform/{request.args["project_id"]}'
  with tempfile.TemporaryDirectory() as workdir:

    result = tasks.tf_init(c, module, workdir, env, prefix, debug)
    if result: return result

    result = tasks.tf_import(c, module, workdir, env, debug, target, resource)
    if result: return result

  return Response(status=200, response=json.dumps({'status':'OK'}, indent=2))
