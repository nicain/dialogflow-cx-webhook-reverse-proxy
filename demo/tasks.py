from invoke import task, context
import json
from flask import Response

TF_PLAN_STORAGE_BUCKET = 'vpc-sc-demo-nicholascain15-tf'


@task
def tf_init(c, module, workdir, env, prefix, debug):
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir={workdir} init -upgrade -reconfigure -backend-config="access_token={env["GOOGLE_OAUTH_ACCESS_TOKEN"]}" -backend-config="bucket={TF_PLAN_STORAGE_BUCKET}" -backend-config="prefix={prefix}"\
  ', warn=True, hide=True, asynchronous=True)
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
def tf_plan(c, module, workdir, env, debug):
  json_option = '-json' if not debug else ''
  promise = c.run(f'\
    cp {module} {workdir} &&\
    terraform -chdir="{workdir}" plan {json_option} -refresh-only -var access_token=\'{env["GOOGLE_OAUTH_ACCESS_TOKEN"]}\'\
  ', warn=True, hide=True, asynchronous=True, env=env)
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
      # 'module.service_perimeter.google_access_context_manager_access_policy.access-policy',
      'module.service_perimeter.google_access_context_manager_service_perimeter.service-perimeter',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.service_perimeter')
    if {
      'module.service_directory.data.google_project.project',
      'module.service_directory.google_service_directory_endpoint.reverse_proxy',
      'module.service_directory.google_service_directory_namespace.reverse_proxy',
      'module.service_directory.google_service_directory_service.reverse_proxy',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.service_directory')
    if {
      'google_project_service.accesscontextmanager',
      'google_project_service.cloudbilling',
      'module.services.google_project_service.appengine',
      'module.services.google_project_service.artifactregistry',
      'google_project_service.cloudbuild',
      'module.services.google_project_service.iam',
      'module.services.google_project_service.run',
      'google_project_service.servicedirectory',
      'module.services.google_project_service.vpcaccess',
      'google_project_service.compute',
      'google_project_service.cloudfunctions',
      'google_project_service.dialogflow',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.services')
    if {
      'module.vpc_network.google_compute_address.reverse_proxy_address',
      'module.vpc_network.google_compute_firewall.allow',
      'module.vpc_network.google_compute_firewall.allow_dialogflow',
      'module.vpc_network.google_compute_network.vpc_network',
      'module.vpc_network.google_compute_router.nat_router',
      'module.vpc_network.google_compute_router_nat.nat_manual',
      'module.vpc_network.google_compute_subnetwork.reverse_proxy_subnetwork',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.vpc_network')
    if {
      'module.webhook_agent.google_cloudfunctions_function.webhook',
      'module.webhook_agent.google_storage_bucket.bucket',
      'module.webhook_agent.google_storage_bucket_object.archive',
      'module.webhook_agent.google_dialogflow_cx_agent.full_agent',
    }.issubset(set(status_dict['resources'])):
      status_dict['resources'].append('module.webhook_agent')
    if {
      'module.webhook_agent',
      'module.vpc_network',
      'module.services',
      'module.service_directory',
      'module.service_perimeter',
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
