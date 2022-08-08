from invoke import task
import json
import pathlib
import jinja2
import requests
import time
import uuid
import base64

BUILD_DIR_DEFAULT = './build'
REGION_DEFAULT = 'us-central1'
CONFIG_FILE_DEFAULT = 'config.json'
WEBHOOK_NAME_DEFAULT = 'custom-telco-webhook'
WEBHOOK_ENTRYPOINT_DEFAULT = 'cxPrebuiltAgentsTelecom'
WEBHOOK_RUNTIME_DEFAULT = 'python39'
SETUP_SA_NAME_DEFAULT = 'sa-setup'
REVERSE_PROXY_SA_NAME_DEFAULT = 'sa-reverse-proxy'
WEBHOOK_INVOKER_SA_NAME_DEFAULT = 'sa-webhook-invoker'
DOMAIN_DEFAULT = 'webhook.internal'
NETWORK_DEFAULT = 'webhook-net'
SUBNET_DEFAULT = 'webhook-subnet'
SUBNET_RANGE_DEFAULT = '10.10.20.0/28'
REVERSE_PROXY_SERVER_DEFAULT = 'webhook-server'
REVERSE_PROXY_SERVER_TAG_DEFAULT = 'latest'
REVERSE_PROXY_SERVER_VM_TAG_DEFAULT = 'webhook-reverse-proxy-vm'
REVERSE_PROXY_SERVER_IP_DEFAULT = '10.10.20.2'
SERVICE_DIRECTORY_NAMESPACE_DEFAULT = 'df-namespace'
SERVICE_DIRECTORY_SERVICE_DEFAULT = 'df-service'
SERVICE_DIRECTORY_ENDPOINT_DEFAULT = 'df-endpoint'
SECURITY_PERIMETER_DEFAULT = 'df_webhook'
DEMO_BACKEND_SA_NAME_DEFAULT = 'demo-backend'

AGENT_SOURCE_URI = 'gs://gassets-api-ai/prebuilt_agents/cx-prebuilt-agents/exported_agent_Telecommunications.blob'
WEBHOOK_PING_DATA = {"fulfillmentInfo":{"tag":"validatePhoneLine"},"sessionInfo":{"parameters":{"phone_number":"123456"}}}


def apply_template(src, tgt, settings):
  with open(src, 'r') as f:
    template = f.read()
  jinja2.Template(template).stream(**settings).dump(str(tgt))


def set_up_service_account(c, sa_name, key_file, project_id, roles):
  sa_iam_account = f'{sa_name}@{project_id}.iam.gserviceaccount.com'
  c.run(f'gcloud iam service-accounts create {sa_name} --display-name={sa_name}', warn=True)
  c.run(f'gcloud iam service-accounts keys create {key_file} --iam-account={sa_iam_account}')
  for role in roles:
    c.run(f'gcloud projects add-iam-policy-binding {project_id} --member=serviceAccount:{sa_iam_account} --role=roles/{role}')


@task
def destroy(c, build_dir):
  c.run(f"rm -rf {build_dir}")


@task
def setup(c,
  principal,
  project_id,
  access_policy,
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  config_file=CONFIG_FILE_DEFAULT,
  clean=False,
  region=REGION_DEFAULT,
  webhook_name=WEBHOOK_NAME_DEFAULT,
  webhook_entrypoint=WEBHOOK_ENTRYPOINT_DEFAULT,
  webhook_runtime=WEBHOOK_RUNTIME_DEFAULT,
  setup_sa_name=SETUP_SA_NAME_DEFAULT,
  reverse_proxy_sa_name=REVERSE_PROXY_SA_NAME_DEFAULT,
  webhook_invoker_sa_name=WEBHOOK_INVOKER_SA_NAME_DEFAULT,
  domain=DOMAIN_DEFAULT,
  network=NETWORK_DEFAULT,
  subnet=SUBNET_DEFAULT,
  subnet_range=SUBNET_RANGE_DEFAULT,
  reverse_proxy_server=REVERSE_PROXY_SERVER_DEFAULT,
  reverse_proxy_server_tag=REVERSE_PROXY_SERVER_TAG_DEFAULT,
  reverse_proxy_server_vm_tag=REVERSE_PROXY_SERVER_VM_TAG_DEFAULT,
  reverse_proxy_server_ip=REVERSE_PROXY_SERVER_IP_DEFAULT,
  service_directory_namespace = SERVICE_DIRECTORY_NAMESPACE_DEFAULT,
  service_directory_service = SERVICE_DIRECTORY_SERVICE_DEFAULT,
  service_directory_endpoint = SERVICE_DIRECTORY_ENDPOINT_DEFAULT,
  security_perimeter = SECURITY_PERIMETER_DEFAULT,
  demo_backend_sa_name = DEMO_BACKEND_SA_NAME_DEFAULT,
):
  if clean:
    destroy(c, build_dir)
  c.run(f"mkdir -p {build_dir}")
  c.run(f"mkdir -p {build_dir}/webhook")
  c.run(f"mkdir -p {build_dir}/server")
  c.run(f"mkdir -p {build_dir}/server/ssl")
  c.run(f"mkdir -p {build_dir}/keys")
  c.run(f"mkdir -p {build_dir}/demo_backend")

  with open(build_dir / config_file, 'w', encoding='utf-8') as f:
    json.dump({
      'PRINCIPAL':principal,
      'PROJECT_ID':project_id,
      'ACCESS_POLICY':access_policy,
      'CONFIG_FILE':config_file,
      'REGION':region,
      'WEBHOOK_NAME':webhook_name,
      'WEBHOOK_ENTRYPOINT':webhook_entrypoint,
      'WEBHOOK_RUNTIME':webhook_runtime,
      'SETUP_SA_NAME':setup_sa_name,
      'REVERSE_PROXY_SA_NAME':reverse_proxy_sa_name,
      'WEBHOOK_INVOKER_SA_NAME':webhook_invoker_sa_name,
      'DOMAIN':domain,
      'NETWORK':network,
      'SUBNET':subnet,
      'SUBNET_RANGE':subnet_range,
      'REVERSE_PROXY_SERVER':reverse_proxy_server,
      'REVERSE_PROXY_SERVER_TAG':reverse_proxy_server_tag,
      'REVERSE_PROXY_SERVER_VM_TAG':reverse_proxy_server_vm_tag,
      'REVERSE_PROXY_SERVER_IP':reverse_proxy_server_ip,
      'SERVICE_DIRECTORY_NAMESPACE':service_directory_namespace,
      'SERVICE_DIRECTORY_SERVICE':service_directory_service,
      'SERVICE_DIRECTORY_ENDPOINT':service_directory_endpoint,
      'SECURITY_PERIMETER':security_perimeter,
      'DEMO_BACKEND_SA_NAME':demo_backend_sa_name,
    }, f, indent=2, sort_keys=True)
    f.write('\n')

@task
def get(c,
  key,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  silent=False,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not silent:
    print(settings[key])
  return settings[key]


@task
def source(c, 
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  stdout=True,
):
  with open(build_dir / config_file, 'r', encoding='utf-8') as f:
    settings = json.load(f)
  settings["PROJECT_NUMBER"] = c.run(f'gcloud projects list --filter={settings["PROJECT_ID"]} --format="value(PROJECT_NUMBER)"', hide=True).stdout.strip()
  settings["WEBHOOK_TRIGGER_URI"] = f'https://{settings["REGION"]}-{settings["PROJECT_ID"]}.cloudfunctions.net/{settings["WEBHOOK_NAME"]}'
  settings["REVERSE_PROXY_SERVER_REPO"] = f'{settings["REVERSE_PROXY_SERVER"]}-repo'
  settings["REVERSE_PROXY_SERVER_IMAGE"] = f'{settings["REVERSE_PROXY_SERVER"]}-image'
  settings["REVERSE_PROXY_SERVER_IMAGE_URI"] = f'{settings["REGION"]}-docker.pkg.dev/{settings["PROJECT_ID"]}/{settings["REVERSE_PROXY_SERVER_REPO"]}/{settings["REVERSE_PROXY_SERVER_IMAGE"]}:{settings["REVERSE_PROXY_SERVER_TAG"]}'
  settings["AGENT_SOURCE_URI"] = AGENT_SOURCE_URI
  settings["ZONE"]=f'{settings["REGION"]}-b'
  if stdout:
    print(json.dumps(settings, indent=2))
  return settings


@task
def login(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  c.run(f'gcloud auth login --quiet {settings["PRINCIPAL"]} --no-launch-browser', hide=True)


@task
def login_sa(c,
  sa_name,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  c.run(f'gcloud auth activate-service-account --key-file={build_dir/"keys"/sa_name}', hide=True)


@task
def init(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  new_project=False,
  organization=None,
):
  settings = source(c, config_file, build_dir, stdout=False)

  if new_project:
    if not organization:
      raise RuntimeError('Need organization to create a project')
    c.run(f'gcloud projects create {settings["PROJECT_ID"]} --organization={organization}')

  c.run(f'gcloud --quiet config set project {settings["PROJECT_ID"]}')


@task
def billing(c,
  account_id,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  c.run(f'gcloud beta billing projects link {settings["PROJECT_ID"]} --billing-account {account_id}')


@task
def configure(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  apis=True,
  service_identities=True,
  service_accounts=True,
  vpc=True,
  storage=True,
):
  settings = source(c, config_file, build_dir, stdout=False)

  # Enable APIs:
  if apis:
    login(c, config_file, build_dir)
    for api in ['compute','iam','dialogflow','servicedirectory','run','cloudbuild','cloudfunctions','artifactregistry','accesscontextmanager']:
      c.run(f'gcloud services enable {api}.googleapis.com')

  # Configure service identity for dialogflow:
  if service_identities:
    login(c, config_file, build_dir)
    c.run('gcloud beta services identity create --service=dialogflow.googleapis.com')
    for role in ['servicedirectory.viewer', 'servicedirectory.pscAuthorizedService']:
      c.run(f'gcloud projects add-iam-policy-binding {settings["PROJECT_ID"]} --member=serviceAccount:service-{settings["PROJECT_NUMBER"]}@gcp-sa-dialogflow.iam.gserviceaccount.com --role=roles/{role}')

  # Configure service account for remaining setup:
  if service_accounts:
    login(c, config_file, build_dir)
    set_up_service_account(c,
      settings["SETUP_SA_NAME"],
      build_dir/"keys"/settings["SETUP_SA_NAME"],
      settings["PROJECT_ID"],
      roles = ['storage.admin', 'compute.admin', 'iam.serviceAccountUser', 'cloudfunctions.developer', 'artifactregistry.admin', 'cloudbuild.builds.editor', 'dialogflow.admin', 'serviceusage.serviceUsageConsumer', 'browser']
    )
    c.run(f'gcloud access-context-manager policies add-iam-policy-binding --member=serviceAccount:{settings["SETUP_SA_NAME"]}@{settings["PROJECT_ID"]}.iam.gserviceaccount.com --role=roles/accesscontextmanager.policyEditor {settings["ACCESS_POLICY"]}', warn=True)
    set_up_service_account(c,
      settings["REVERSE_PROXY_SA_NAME"],
      build_dir/"keys"/settings["REVERSE_PROXY_SA_NAME"],
      settings["PROJECT_ID"],
      roles = []
    )
    set_up_service_account(c,
      settings["WEBHOOK_INVOKER_SA_NAME"],
      build_dir/"keys"/settings["WEBHOOK_INVOKER_SA_NAME"],
      settings["PROJECT_ID"],
      roles = ['cloudfunctions.invoker']
    )
    set_up_service_account(c,
      settings["DEMO_BACKEND_SA_NAME"],
      build_dir/"keys"/settings["DEMO_BACKEND_SA_NAME"],
      settings["PROJECT_ID"],
      roles = ['cloudfunctions.editor', 'browser', 'accesscontextmanager.policyEditor']
    )
    c.run(f'gcloud access-context-manager policies add-iam-policy-binding --member=serviceAccount:{settings["SETUP_SA_NAME"]}@{settings["PROJECT_ID"]}.iam.gserviceaccount.com --role=roles/accesscontextmanager.policyEditor {settings["ACCESS_POLICY"]}', warn=True)

  # Configure Network:
  if vpc:
    login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)
    c.run(f'gcloud compute networks create {settings["NETWORK"]} --project={settings["PROJECT_ID"]} --subnet-mode=custom', warn=True)
    c.run(f'gcloud compute firewall-rules create allow --network {settings["NETWORK"]} --allow tcp:22,tcp:3389,icmp', warn=True)
    c.run(f'gcloud compute firewall-rules create allow-dialogflow \
      --direction=INGRESS \
      --priority=1000 \
      --network={settings["NETWORK"]} \
      --action=ALLOW \
      --rules=tcp:443 \
      --source-ranges=35.199.192.0/19 \
      --target-tags={settings["REVERSE_PROXY_SERVER_VM_TAG"]}')
    c.run(f'gcloud compute networks subnets create {settings["SUBNET"]} \
      --project={settings["PROJECT_ID"]} \
      --network={settings["NETWORK"]} \
      --region={settings["REGION"]} \
      --enable-private-ip-google-access \
      --range={settings["SUBNET_RANGE"]}', warn=True)
    c.run(f'gcloud compute routers create nat-router \
      --network={settings["NETWORK"]} \
      --region={settings["REGION"]}', warn=True)
    c.run(f'gcloud compute routers nats create nat-config \
      --router=nat-router \
      --auto-allocate-nat-external-ips \
      --nat-all-subnet-ip-ranges \
      --enable-logging \
      --router-region={settings["REGION"]}', warn=True)
  
  if storage:
    login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)
    c.run(f'gsutil mb gs://{settings["PROJECT_ID"]}', warn=True)

@task
def deploy_webhook(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  template_dir=pathlib.Path('templates'),
  allow_unauthenticated=True,
  ingress_settings='all',
  sa_name=None,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not sa_name:
    sa_name = settings["SETUP_SA_NAME"]

  src = template_dir/"webhook"/"main.py.j2"
  tgt = build_dir/"webhook"/"main.py"
  apply_template(src, tgt, settings)

  c.run(f'cp {template_dir/"webhook"/"helpers.py"} {build_dir/"webhook"/"helpers.py"}')
  c.run(f'cp {template_dir/"webhook"/"requirements.txt"} {build_dir/"webhook"/"requirements.txt"}')
  c.run(f'cd {build_dir/"webhook"} && zip webhook.zip *', hide=True)
  c.run(f'gsutil cp -r {build_dir/"webhook/webhook.zip"} gs://{settings["PROJECT_ID"]}')

  if allow_unauthenticated:
    authenticated = '--allow-unauthenticated'
  else:
    authenticated = '--no-allow-unauthenticated'
  c.run(f'gcloud functions deploy {settings["WEBHOOK_NAME"]} {authenticated} --ingress-settings={ingress_settings} --entry-point {settings["WEBHOOK_ENTRYPOINT"]} --runtime {settings["WEBHOOK_RUNTIME"]} --trigger-http --source=gs://{settings["PROJECT_ID"]}"/webhook.zip"')


@task
def update_webhook(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  allow_unauthenticated=True,
  ingress_settings='all',
  sa_name=None,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not sa_name:
    sa_name = settings["SETUP_SA_NAME"]
  if allow_unauthenticated:
    authenticated = '--allow-unauthenticated'
  else:
    authenticated = '--no-allow-unauthenticated'
  result = c.run(f'gcloud functions deploy --project={settings["PROJECT_ID"]} {settings["WEBHOOK_NAME"]} {authenticated} --ingress-settings={ingress_settings}', hide=True)
  if result.stderr:
    return {'status': 500, 'response':result.stderr.strip()}
  else:
    return {'status': 200, 'response':result.stdout.strip()}


@task
def ping_webhook(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  authenticated=True,
  sa_name=None,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not sa_name:
    sa_name = settings["WEBHOOK_INVOKER_SA_NAME"]
  login_sa(c, sa_name, config_file, build_dir)
  new_headers = {}
  new_headers['Content-type'] = 'application/json'
  if authenticated:
    token = c.run('gcloud auth print-identity-token', hide=True).stdout.strip()
    new_headers['Authorization'] = f'Bearer {token}'
  result = requests.post(settings["WEBHOOK_TRIGGER_URI"], json=WEBHOOK_PING_DATA, headers=new_headers)
  print(result.text.strip())
  return {'status': result.status_code, 'response':result.text.strip()}


@task
def deploy_reverse_proxy_server(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  template_dir=pathlib.Path('templates'),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  for filename in ['app.py', 'startup_script.sh']:
    src = template_dir/'server'/f'{filename}.j2'
    tgt = build_dir/'server'/f'{filename}'
    apply_template(src, tgt, settings)

  for filename in ['Dockerfile', 'Procfile', 'requirements.txt']:
    c.run(f'cp {template_dir/"server"/filename} {build_dir/"server"/filename}')

  # Create TLS keys:
  ssl_key = build_dir/'server/ssl/server.key'
  ssl_csr = build_dir/'server/ssl/server.csr'
  ssl_crt = build_dir/'server/ssl/server.crt'
  ssl_der = build_dir/'server/ssl/server.der'
  c.run(f'openssl genrsa -out {ssl_key} 2048')
  c.run(f'openssl req -nodes -new -sha256 -key {ssl_key} -subj "/CN={settings["DOMAIN"]}" -out {ssl_csr}')
  c.run(f'openssl x509 -req -days 3650 -in {ssl_csr} -signkey {ssl_key} -out {ssl_crt} -extfile <(printf "\nsubjectAltName=\'DNS:{settings["DOMAIN"]}")')
  c.run(f'openssl x509 -in {ssl_crt} -out {ssl_der} -outform DER')
  c.run(f'gsutil cp -r {build_dir/"server/ssl"} gs://{settings["PROJECT_ID"]}')

  # Build docker image
  c.run(f'gcloud auth configure-docker {settings["REGION"]}-docker.pkg.dev')
  c.run(f'gcloud artifacts repositories create {settings["REVERSE_PROXY_SERVER_REPO"]} --location {settings["REGION"]} --repository-format "docker"', warn=True)
  c.run(f'gcloud builds submit {build_dir/"server"} --pack image={settings["REVERSE_PROXY_SERVER_IMAGE_URI"]} --gcs-log-dir=gs://{settings["PROJECT_ID"]}/{settings["REVERSE_PROXY_SERVER_IMAGE"]}-build-logs')

  # Deploy reverse proxy server
  c.run(f'gcloud compute instances create {settings["REVERSE_PROXY_SERVER"]} \
    --project={settings["PROJECT_ID"]} \
    --zone={settings["ZONE"]} \
    --tags={settings["REVERSE_PROXY_SERVER_VM_TAG"]} \
    --scopes=cloud-platform \
    --create-disk=auto-delete=yes,boot=yes,device-name=instance-1,image=projects/debian-cloud/global/images/debian-10-buster-v20220406,mode=rw,size=10,type=projects/{settings["PROJECT_ID"]}/zones/{settings["ZONE"]}/diskTypes/pd-balanced \
    --network-interface=network={settings["NETWORK"]},subnet={settings["SUBNET"]},no-address,private-network-ip={settings["REVERSE_PROXY_SERVER_IP"]} \
    --metadata-from-file=startup-script={build_dir/"server/startup_script.sh"}')

  # Wait for server to start up:
  print('Waiting for server initialization...')
  while True:
    if not startup_poll(c):
      print('  Still waiting...')
    else:
      print('  Server initializated')
      break


@task
def startup_poll(c):
  result = c.run('gcloud compute instances get-serial-port-output --start=0 $(inv get REVERSE_PROXY_SERVER) --zone=$(inv get ZONE) | grep "google-startup-scripts.service: Succeeded"', hide=True, warn=True)
  if 'google-startup-scripts.service: Succeeded.' in result.stdout.strip():
    return True
  else:
    time.sleep(5)
    return False


@task
def ping_webhook_from_reverse_proxy_server(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)

  login_sa(c, settings["WEBHOOK_INVOKER_SA_NAME"], config_file, build_dir)
  token = c.run('gcloud auth print-identity-token', hide=True).stdout.strip()

  login(c, config_file, build_dir)
  ping_command = f'echo quit | openssl s_client -showcerts -servername {settings["DOMAIN"]} -connect {settings["REVERSE_PROXY_SERVER_IP"]}:443 > webhook-reverse-proxy-server.pem && curl -X POST  --resolve {settings["DOMAIN"]}:443:127.0.0.1 --cacert webhook-reverse-proxy-server.pem -H "Authorization: Bearer {token}" -H "Content-Type:application/json" --data @/etc/docker/ping-payload.json https://{settings["DOMAIN"]}'
  result = c.run(f'gcloud compute ssh {settings["REVERSE_PROXY_SERVER"]} --project={settings["PROJECT_ID"]} --zone={settings["ZONE"]} --command=\'{ping_command}\'', hide=True)
  print(result.stdout.strip())
  return


@task
def ping_webhook_from_vpc(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)

  login_sa(c, settings["WEBHOOK_INVOKER_SA_NAME"], config_file, build_dir)
  token = c.run('gcloud auth print-identity-token', hide=True).stdout.strip()

  login(c, config_file, build_dir)
  ping_command = f'curl -X POST -H "Authorization: Bearer {token}" -H "Content-Type:application/json" --data @/etc/docker/ping-payload.json {settings["WEBHOOK_TRIGGER_URI"]}'
  result = c.run(f'gcloud compute ssh {settings["REVERSE_PROXY_SERVER"]} --project={settings["PROJECT_ID"]} --zone={settings["ZONE"]} --command=\'{ping_command}\'', hide=True)
  print(result.stdout.strip())
  return


@task
def deploy_agent(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  # # Create service directory:
  # c.run(f'gcloud service-directory namespaces create {settings["SERVICE_DIRECTORY_NAMESPACE"]} --location {settings["REGION"]}', warn=True)
  # c.run(f'gcloud service-directory services create {settings["SERVICE_DIRECTORY_SERVICE"]} --namespace {settings["SERVICE_DIRECTORY_NAMESPACE"]} --location {settings["REGION"]}', warn=True)
  # c.run(f'gcloud service-directory endpoints create {settings["SERVICE_DIRECTORY_ENDPOINT"]} \
  #   --service={settings["SERVICE_DIRECTORY_SERVICE"]} \
  #   --namespace={settings["SERVICE_DIRECTORY_NAMESPACE"]} \
  #   --location={settings["REGION"]} \
  #   --address={settings["REVERSE_PROXY_SERVER_IP"]} \
  #   --port=443 \
  #   --network=projects/{settings["PROJECT_NUMBER"]}/locations/global/networks/{settings["NETWORK"]}', warn=True)

  # # Create Telecommunications agent:
  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  # data = json.dumps({"displayName": "Telecommunications","defaultLanguageCode": "en","timeZone": "America/Chicago"})
  # c.run(f'curl -s -X POST -H "Authorization: Bearer {token}" -H "Content-Type:application/json" -H "x-goog-user-project: {settings["PROJECT_ID"]}" -d \'{data}\' "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/projects/{settings["PROJECT_ID"]}/locations/{settings["REGION"]}/agents"', warn=True)
  agent_name = get_agents(c)['Telecommunications']['name']
  # data = json.dumps({"agentUri": AGENT_SOURCE_URI})
  # c.run(f'curl -s -X POST -H "Authorization: Bearer {token}" -H "Content-Type:application/json" -H "x-goog-user-project: {settings["PROJECT_ID"]}" -d \'{data}\' "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{agent_name}:restore"')

  # Update the agent to query the webhook URI:
  webhook_name = get_webhooks(c, agent_name)['cxPrebuiltAgentsTelecom']['name']
  data = json.dumps({"displayName": "cxPrebuiltAgentsTelecom", "genericWebService": {"uri": settings["WEBHOOK_TRIGGER_URI"]}})
  c.run(f'curl -s -X PATCH -H "Authorization: Bearer {token}" -H "Content-Type:application/json" -H "x-goog-user-project: {settings["PROJECT_ID"]}" -d \'{data}\' "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{webhook_name}"')


@task
def get_agents(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  result = c.run(f'curl -s -X GET -H "Authorization: Bearer {token}" -H "x-goog-user-project: {settings["PROJECT_ID"]}" "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/projects/{settings["PROJECT_ID"]}/locations/{settings["REGION"]}/agents"', warn=True, hide=True)
  agents = json.loads(result.stdout.strip())
  return {data['displayName']:data for data in agents['agents']}


@task
def get_webhooks(c,
  agent_name,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)
  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  result = c.run(f'curl -s -X GET -H "Authorization: Bearer {token}" -H "x-goog-user-project: {settings["PROJECT_ID"]}" "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{agent_name}/webhooks"', warn=True, hide=True)
  agents = json.loads(result.stdout.strip())
  return {data['displayName']:data for data in agents['webhooks']}


@task
def get_flows(c,
  agent_name,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  result = c.run(f'curl -s -X GET -H "Authorization: Bearer {token}" -H "x-goog-user-project: {settings["PROJECT_ID"]}" "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{agent_name}/flows"', warn=True, hide=True)
  flows = json.loads(result.stdout.strip())
  return {data['displayName']:data for data in flows['flows']}


@task
def get_pages(c,
  flow_name,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  result = c.run(f'curl -s -X GET -H "Authorization: Bearer {token}" -H "x-goog-user-project: {settings["PROJECT_ID"]}" "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{flow_name}/pages"', warn=True, hide=True)
  pages = json.loads(result.stdout.strip())
  return {data['displayName']:data for data in pages['pages']}


@task
def ping_agent(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)

  agent_name = get_agents(c)['Telecommunications']['name']
  flow_name = get_flows(c, agent_name)['Cruise Plan']['name']
  page_name = get_pages(c, flow_name)['Collect Customer Line']['name']
  session_id = str(uuid.uuid1())

  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  data = json.dumps({
      "queryInput": {"languageCode": "en", "text": {"text": "123456"}},
      "queryParams": {"currentPage": page_name}
    })
  result = c.run(f'curl -s -X POST -H "Authorization: Bearer {token}" -H "Content-Type:application/json" -H "x-goog-user-project: {settings["PROJECT_ID"]}" -d \'{data}\' "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{agent_name}/sessions/{session_id}:detectIntent"', warn=True, hide=True)
  print(json.loads(result.stdout.strip())['queryResult']['responseMessages'][0]['text']['text'][0]) 


@task
def ping_agent_from_vpc(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  template_dir=pathlib.Path('templates'),
):
  settings = source(c, config_file, build_dir, stdout=False)
  login(c, config_file, build_dir)

  src = template_dir/"ping_agent.sh.j2"
  tgt = build_dir/"ping_agent.sh"
  apply_template(src, tgt, settings)
  c.run(f'cat {tgt} | gcloud compute ssh {settings["REVERSE_PROXY_SERVER"]} --project={settings["PROJECT_ID"]} --zone={settings["ZONE"]} --command="bash -s"')


@task
def update_agent_webhook(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  # data = json.dumps({"displayName": "cxPrebuiltAgentsTelecom", "genericWebService": {"uri": settings["WEBHOOK_TRIGGER_URI"]}})
  settings = source(c, config_file, build_dir, stdout=False)
  login_sa(c, settings["SETUP_SA_NAME"], config_file, build_dir)


  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()

  def b64Encode(msg_bytes):
      base64_bytes = base64.b64encode(msg_bytes)
      return base64_bytes.decode('ascii')

  service = f'projects/vpc-sc-demo-nicholascain10/locations/us-central1/namespaces/df-namespace/services/df-service'
  with open(build_dir/'server/ssl/server.der', 'rb') as f:
    allowed_ca_cert = f.read()
  agent_name = get_agents(c)['Telecommunications']['name']
  webhook_name = get_webhooks(c, agent_name)['cxPrebuiltAgentsTelecom']['name']
  data = json.dumps({
    "displayName": "cxPrebuiltAgentsTelecom", 
    "serviceDirectory": {
      "service": service,
      "genericWebService": {
        "uri": f'https://{settings["DOMAIN"]}',
        "allowedCaCerts": [b64Encode(allowed_ca_cert)]
      }
    }
  })
  c.run(f'curl -s -X PATCH -H "Authorization: Bearer {token}" -H "Content-Type:application/json" -H "x-goog-user-project: {settings["PROJECT_ID"]}" -d \'{data}\' "https://{settings["REGION"]}-dialogflow.googleapis.com/v3/{webhook_name}"')



@task
def get_project_ancestor(c,
  ancestor_type=None,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  sa_name=None,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not sa_name:
    sa_name = settings["SETUP_SA_NAME"]
  login_sa(c, sa_name, config_file, build_dir)

  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  result = c.run(f'curl -s -X POST -H "Authorization: Bearer {token}" "https://cloudresourcemanager.googleapis.com/v1/projects/{settings["PROJECT_ID"]}:getAncestry"', warn=True, hide=True)
  for ancestor_dict in json.loads(result.stdout.strip())['ancestor']:
    if ancestor_dict["resourceId"]["type"] == ancestor_type:
      return ancestor_dict["resourceId"]["id"]


@task
def create_security_perimeter(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
):
  settings = source(c, config_file, build_dir, stdout=False)

  # Get Access policy info:
  access_policy_id = settings["ACCESS_POLICY"].split('/')[1]
  
  # Break out early if perimeter already exists:
  token = c.run('gcloud auth print-access-token', hide=True).stdout.strip()
  headers = {}
  headers['Authorization'] = f'Bearer {token}'
  response_json = requests.get(f'https://accesscontextmanager.googleapis.com/v1/{access_policy_name}/servicePerimeters', headers=headers).json()
  if response_json:
    for service_perimeter in response_json['servicePerimeters']:
      if service_perimeter['title'] == settings["SECURITY_PERIMETER"]:
        return

  # Create the perimeter:
  c.run(f'gcloud access-context-manager perimeters create {settings["SECURITY_PERIMETER"]} --policy={access_policy_id} --title={settings["SECURITY_PERIMETER"]} --resources=projects/{settings["PROJECT_NUMBER"]}')

@task
def update_security_perimeter(c,
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  restrict_dialogflow=True,
  restrict_cloudfunctions=True,
  sa_name=None,
):
  settings = source(c, config_file, build_dir, stdout=False)
  if not sa_name:
    sa_name = settings["SETUP_SA_NAME"]

  # Get Access policy info:
  access_policy_id = settings["ACCESS_POLICY"].split('/')[1]

  restricted_services = []
  if restrict_dialogflow:
    restricted_services.append('dialogflow.googleapis.com')
  if restrict_cloudfunctions:
    restricted_services.append('cloudfunctions.googleapis.com')

  login_sa(c, sa_name, config_file, build_dir)
  result = c.run(f'gcloud access-context-manager perimeters update {settings["SECURITY_PERIMETER"]} --policy={access_policy_id} --set-restricted-services={",".join(restricted_services)}', hide=True)
  if result.stderr:
    return {'status': 500, 'response':result.stderr.strip()}
  else:
    return {'status': 200, 'response':result.stdout.strip()}


@task
def deploy_demo(c,
  build_dir=pathlib.Path(BUILD_DIR_DEFAULT),
  template_dir=pathlib.Path('templates'),
  config_file=pathlib.Path(CONFIG_FILE_DEFAULT),
  debug=True,
):
  settings = source(c, config_file, build_dir, stdout=False)

  for filename in ['Dockerfile', 'Procfile', 'requirements.txt']:
    c.run(f'cp {template_dir/"demo_backend"/filename} {build_dir/"demo_backend"/filename}')
  for filename in ['app.py']:
    src = template_dir/'demo_backend'/f'{filename}.j2'
    tgt = build_dir/'demo_backend'/f'{filename}'
    apply_template(src, tgt, settings)


  c.run(f'cp tasks.py {build_dir/"demo_backend/tasks.py"}')
  c.run(f'cp {build_dir/config_file} {build_dir/"demo_backend/config.json"}')
  c.run(f'cp {build_dir/"keys"/settings["DEMO_BACKEND_SA_NAME"]} {build_dir/"demo_backend"/settings["DEMO_BACKEND_SA_NAME"]}')

  if debug:
    c.run(f'cd {build_dir/"demo_backend"} && sudo docker run -p 127.0.0.1:5000:5000 --rm -it $(sudo docker build -q .)', pty=True)

'''
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
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
  https://accesscontextmanager.googleapis.com/v1/{servicePerimeter.name=accessPolicies/*/servicePerimeters/*}
'''