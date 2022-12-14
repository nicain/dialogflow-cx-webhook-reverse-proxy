from invoke import task, context
import json
from flask import Response
import google.auth.transport.requests
from google.oauth2 import service_account


TF_PLAN_STORAGE_BUCKET = 'vpc-sc-demo-nicholascain15-tf'


@task
def tf_init(c, module, workdir, env, prefix, debug):
  user_access_token = env.pop("GOOGLE_OAUTH_ACCESS_TOKEN")

  credentials = service_account.Credentials.from_service_account_file(
    '/app/demo-server-key.json', 
    scopes=['https://www.googleapis.com/auth/cloud-platform']
  )
  request = google.auth.transport.requests.Request()
  credentials.refresh(request)
  env["GOOGLE_OAUTH_ACCESS_TOKEN"] = credentials.token
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir={workdir} init -upgrade -reconfigure -backend-config="access_token={env["GOOGLE_OAUTH_ACCESS_TOKEN"]}" -backend-config="bucket={TF_PLAN_STORAGE_BUCKET}" -backend-config="prefix={prefix}"\
  ', warn=True, hide=True, asynchronous=True)
  result = promise.join()
  env["GOOGLE_OAUTH_ACCESS_TOKEN"] = user_access_token

  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)

  if result.exited:
    return Response(status=500, response=json.dumps({
      'status': 'ERROR',
      'stdout': result.stdout,
      'stderr': result.stderr,
    }))


@task
def tf_plan(c, module, workdir, env, debug, target=None):
  target_option = f'-target={target}' if target else ''
  json_option = '-json' if not debug else ''
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir="{workdir}" plan {json_option} -refresh-only -var access_token=\'{env["GOOGLE_OAUTH_ACCESS_TOKEN"]}\' {target_option}\
  ', warn=True, hide=True, asynchronous=True, env=env)
  result = promise.join()

  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)
  else:
    errors = []
    hooks = {
      'refresh_start':[], 
      'refresh_complete':[], 
      'apply_complete':[],
      'apply_start': [],
    }
    lines = result.stdout.split('\n')
    for line in lines:
      if line.strip():
        try:
          message = json.loads(line.strip())
          if message["@level"] == "error":
            errors.append(message)
          if 'hook' in message:
            hooks[message['type']].append(message['hook'])
        except Exception as e:
          print("COULD NOT LOAD", repr(line), type(e), e)
    if errors:
      return {
        'response': 
        Response(status=500, response=json.dumps({
          'status': 'ERROR',
          'errors': errors,
        }))
      }
    return {'hooks': hooks}


@task
def tf_apply(c, module, workdir, env, debug, destroy, target=None, verbose=False):
  target_option = f'-target={target}' if target else ''
  json_option = '-json' if not debug else ''
  destroy_option = '--destroy' if destroy == True else ''
  verbose_option = 'export TF_LOG="DEBUG" &&' if verbose else ''

  promise = c.run(f'\
    cp {module} {workdir} &&\
    {verbose_option}\
    terraform -chdir="{workdir}" apply -lock-timeout=10s {json_option} --auto-approve -var access_token=\'{env["GOOGLE_OAUTH_ACCESS_TOKEN"]}\' {destroy_option} {target_option}\
  ', warn=True, hide=None, asynchronous=True, env=env)
  result = promise.join()
  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)
  else:
    errors = []
    lines = result.stdout.split('\n')
    for line in lines:
      if line.strip():
        try:
          message = json.loads(line)
          if message["@level"] == "error":
            errors.append(message)
        except:
          print("COULD NOT LOAD", line)
    if errors:
      return Response(status=500, response=json.dumps({
        'status': 'ERROR',
        'errors': errors,
      }))

@task
def tf_state_list(c, module, workdir, env, debug):
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir="{workdir}" state list', warn=True, hide=True, asynchronous=True, env=env)
  result = promise.join()

  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)

  if result.exited:
    return {'response':Response(status=500, response=json.dumps({
      'status': 'ERROR',
      'stdout': result.stdout,
      'stderr': result.stderr,
    }))}
  else:
    status_dict = {'resources': result.stdout.split()}
    if {
      'module.service_directory.google_service_directory_endpoint.reverse_proxy',
      'module.service_directory.google_service_directory_namespace.reverse_proxy',
      'module.service_directory.google_service_directory_service.reverse_proxy',
      'module.service_perimeter.google_access_context_manager_service_perimeter.service_perimeter[0]',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.service_directory')
    if {
      'module.services.google_project_service.appengine',
      'module.services.google_project_service.artifactregistry',
      'module.services.google_project_service.run',
      'module.services.google_project_service.vpcaccess',
      'google_project_service.accesscontextmanager',
      'google_project_service.cloudbilling',
      'google_project_service.cloudbuild',
      'google_project_service.cloudfunctions',
      'google_project_service.compute',
      'google_project_service.dialogflow',
      'google_project_service.iam',
      'google_project_service.servicedirectory',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.services')
    if {
      'module.vpc_network.google_artifact_registry_repository.webhook_registry',
      'module.vpc_network.google_cloudbuild_trigger.reverse_proxy_server',
      'module.vpc_network.google_compute_address.reverse_proxy_address',
      'module.vpc_network.google_compute_firewall.allow',
      'module.vpc_network.google_compute_firewall.allow_dialogflow',
      'module.vpc_network.google_compute_instance.reverse_proxy_server',
      'module.vpc_network.google_compute_network.vpc_network',
      'module.vpc_network.google_compute_router.nat_router',
      'module.vpc_network.google_compute_router_nat.nat_manual',
      'module.vpc_network.google_compute_subnetwork.reverse_proxy_subnetwork',
      'module.vpc_network.google_project_iam_member.dfsa_sd_pscAuthorizedService',
      'module.vpc_network.google_project_iam_member.dfsa_sd_viewer',
      'module.vpc_network.google_project_service_identity.dfsa',
      'module.vpc_network.google_pubsub_topic.reverse_proxy_server_build',
      'module.vpc_network.google_storage_bucket_object.proxy_server_source',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.vpc_network')
    if {
      'module.webhook_agent.google_cloudfunctions_function.webhook',
      'google_storage_bucket.bucket',
      'module.webhook_agent.google_storage_bucket_object.webhook',
      'module.webhook_agent.google_dialogflow_cx_agent.full_agent',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.webhook_agent')
    if {
      'module.webhook_agent',
      'module.vpc_network',
      'module.services',
      'module.service_directory',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('all')
    print(status_dict['resources'])
    return status_dict


@task
def tf_unlock(c, module, workdir, env, debug, lock_id):
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir={workdir} force-unlock -force {lock_id}\
  ', warn=True, hide=True, asynchronous=True, env=env)
  result = promise.join()

  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)

  if result.exited:
    return Response(status=500, response=json.dumps({
      'status': 'ERROR',
      'stdout': result.stdout,
      'stderr': result.stderr,
    }))

@task
def tf_import(c, module, workdir, env, debug, target, resource):
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir={workdir} import -var access_token=\'{env["GOOGLE_OAUTH_ACCESS_TOKEN"]}\' "{target}" "{resource}"\
  ', warn=True, hide=True, asynchronous=True, env=env)
  result = promise.join()

  if debug:
    print(result.exited)
    print(result.stdout)
    print(result.stderr)
