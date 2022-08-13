from flask import Flask, request, Response, abort, render_template
from turbo_flask import Turbo
import os
import tasks
import invoke
import pathlib
import logging
import time
import json
import threading

from google.oauth2 import id_token
from google.auth.transport import requests as reqs

app = Flask(__name__)
turbo = Turbo(app)
gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

CONFIG_FILE=os.environ['CONFIG_FILE']
SA_NAME=os.environ['DEMO_BACKEND_SA_NAME']
PRINCIPAL=os.environ['PRINCIPAL']
PROJECT_ID=os.environ['PROJECT_ID']

BUILD_DIR=pathlib.Path('.')
tasks.login_sa(invoke.Context(), 'demo-backend', build_dir=BUILD_DIR)

authorized_emails = [
    PRINCIPAL,
    f'{SA_NAME}@{PROJECT_ID}.iam.gserviceaccount.com',
]

def update_project_status():
  with app.app_context():
    while True:
      time.sleep(.5)
      turbo.push(turbo.replace(render_template('cloudfunctions_restricted.html'), 'cloudfunctions_restricted_anchor'))
      turbo.push(turbo.replace(render_template('dialogflow_restricted.html'), 'dialogflow_restricted_anchor'))
      print('PUSH')
# ['restricted_services','webhook_fulfillment','webhook_ingress','webhook_access']


class ProjectStatus:
  def __init__(self):
    self.cloudfunctions_restricted = None
    self.dialogflow_restricted = None

status = ProjectStatus()

def poll_restricted_services():
  while True:
    result = tasks.get_status(
      invoke.Context(),
      config_file=CONFIG_FILE, build_dir=BUILD_DIR,
      sa_name=SA_NAME,
      restricted_services=True,
      webhook_fulfillment=False,
      webhook_ingress=False,
      webhook_access=False,
      skip_setup=True,
    )
    result_dict = json.loads(result['response'])
    status.cloudfunctions_restricted = result_dict['cloudfunctions_restricted']
    status.dialogflow_restricted = result_dict['dialogflow_restricted']
    print('POLL')


@app.before_first_request
def other_before_first_request():
    threading.Thread(target=update_project_status).start()
    threading.Thread(target=poll_restricted_services).start()


@app.context_processor
def inject_status_into_context():
    return {
      'cloudfunctions_restricted': status.cloudfunctions_restricted,
      'dialogflow_restricted':  status.dialogflow_restricted,
    }


# @app.before_request
def check_user_authentication():

  if request.endpoint is None:
    abort(405, {'message': 'Requested endpoint/method not recognized'})

  app.logger.info('[0] Begin check_user_authentication')

  if request.endpoint == 'ping_webhook' and request.args['authenticated'] == 'false':
    app.logger.info(f'[0]   Skipping Authorization Check:')
    return

  verified_email = None

  auth = request.headers.get("Authorization", None)

  if auth is None:
    return abort(403)

  if not auth.startswith("Bearer "):
    return abort(403)

  token = auth[7:]  # Remove "Bearer: " prefix

  # Extract the email address from the token. Since there may be
  # two types of token provided (Firebase or Google OAuth2) and
  # failed verification raises an exception, need multiple
  # try/except blocks.

  info = None
  try:
    info = id_token.verify_firebase_token(token, reqs.Request())
  except ValueError:
    pass

  try:
    if info is None:
      info = id_token.verify_oauth2_token(token, reqs.Request())
  except ValueError:
    pass

  if info is None:
    return abort(403)

  if "email" not in info:
    return abort(403)

  verified_email = info["email"]
  app.logger.info(f'[0]   User: {verified_email}')
  if verified_email not in authorized_emails:
    return abort(403)
  app.logger.info(f'[0]   Authorized: {verified_email}')


@app.route('/')
def home():
  return render_template('index.html')


@app.route('/configuration', methods=['GET'])
def configuration():

  configuration_dict = {}
  for key in request.args:
    configuration_dict[key] = tasks.get(invoke.Context(), key, config_file=CONFIG_FILE, build_dir=BUILD_DIR)
  return configuration_dict


@app.route('/ping_agent', methods=['GET'])
def ping_agent():
  app.logger.info('ping_agent:')
  result_dict = tasks.ping_agent(invoke.Context(), sa_name=SA_NAME, config_file=CONFIG_FILE, build_dir=BUILD_DIR)
  app.logger.info(f'  ping_agent: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/ping_webhook', methods=['GET'])
def ping_webhook():
  app.logger.info('ping_webhook:')
  if request.args['authenticated'] == 'true':
    authenticated = True
  elif request.args['authenticated'] == 'false':
    authenticated = False
  else:
    return Response(status=400, response=f'Value for "authenticated" must be one of [true, false], received: "{request.args["authenticated"]}"')
  app.logger.info(f'  authenticated: {authenticated}')
  result_dict = tasks.ping_webhook(invoke.Context(), sa_name=SA_NAME, authenticated=authenticated, config_file=CONFIG_FILE, build_dir=BUILD_DIR)
  app.logger.info(f'  ping_webhook: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/update_webhook_access', methods=['POST'])
def update_webhook_access():
  app.logger.info('update_webhook_access:')
  content = request.get_json(silent=True)

  allow_unauthenticated = content['allow_unauthenticated']
  app.logger.info(f'  allow_unauthenticated: {allow_unauthenticated}')

  result_dict = tasks.update_webhook_access(invoke.Context(), 
    sa_name=SA_NAME,
    allow_unauthenticated=allow_unauthenticated,
    config_file=CONFIG_FILE, build_dir=BUILD_DIR)
  app.logger.info(f'  update_webhook_access: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/update_webhook_ingress', methods=['POST'])
def update_webhook_ingress():
  app.logger.info('update_webhook_ingress:')
  content = request.get_json(silent=True)

  internal_only = content['internal_only']
  app.logger.info(f'  internal_only: {internal_only}')

  result_dict = tasks.update_webhook_ingress(invoke.Context(),
    sa_name=SA_NAME,
    internal_only=internal_only,
    config_file=CONFIG_FILE, build_dir=BUILD_DIR)
  app.logger.info(f'  update_webhook_ingress: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/update_security_perimeter', methods=['POST'])
def update_security_perimeter():
  app.logger.info('update_security_perimeter:')
  content = request.get_json(silent=True)
  api = content['api']
  app.logger.info(f'  api: {api}')
  restricted = content['restricted']
  app.logger.info(f'  restricted: {restricted}')
  result_dict = tasks.update_security_perimeter(
    invoke.Context(),
    config_file=CONFIG_FILE, build_dir=BUILD_DIR,
    api=api,
    restricted=restricted,
    sa_name=SA_NAME,
  )
  app.logger.info(f'  update_security_perimeter: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/update_agent_webhook', methods=['POST'])
def update_agent_webhook():
  app.logger.info('update_agent_webhook:')
  content = request.get_json(silent=True)
  fulfillment = content['fulfillment']
  app.logger.info(f'  fulfillment: {fulfillment}')
  result_dict = tasks.update_agent_webhook(
    invoke.Context(),
    fulfillment=fulfillment,
    config_file=CONFIG_FILE, build_dir=BUILD_DIR,
    sa_name=SA_NAME,
  )
  app.logger.info(f'  update_security_perimeter: {result_dict["status"]}')
  return Response(**result_dict)


@app.route('/get_status', methods=['GET'])
def get_status():
  app.logger.info('get_status:')


  kwargs ={}
  for key in ['restricted_services','webhook_fulfillment','webhook_ingress','webhook_access']:
    if request.args.get(key, 'false') == 'true':
      kwargs[key] = True
    elif request.args.get(key, 'false') == 'false':
      kwargs[key] = False
    else:
      return Response(status=400, response=f'Value for "{key}" must be one of [true, false], received: "{request.args[key]}"')

  result_dict = tasks.get_status(
    invoke.Context(),
    config_file=CONFIG_FILE, build_dir=BUILD_DIR,
    sa_name=SA_NAME,
    **kwargs,
  )
  app.logger.info(f'  get_status: {result_dict["status"]}')
  return Response(**result_dict)


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)