import {useState} from "react";
import {TIMER_SCALE} from "./StatusPollToggle.js"

const project_id_default = "vpc-sc-demo-nicholascain15";
const webhook_name_default = "custom-telco-webhook";
const region_default = "us-central1";
const access_policy_title_default = "vpcsc_demo_policy";

class ReversibleMap {
  constructor(map) {
     this.map = map;
     this.reverseMap = map;
     for(const key in map) {
        const value = map[key];
        this.reverseMap[value] = key;   
     }
  }
  get(key) { return this.map[key]; }
  revGet(key) { return this.reverseMap[key]; }
  set(key, value) { 
    this.map[key] = value;
    this.reverseMap[value] = key;
  }
  unset(key) { 
    delete this.reverseMap[this.map[key]]
    delete this.map[key] 
  }
  revUnset(key) { 
    delete this.map[this.reverseMap[key]]
    delete this.reverseMap[key]
  }
}

function BuildMapPageNumberToState () {
  const order = new ReversibleMap({})
  order.set("dialogflowRestrictedState",0)  
  order.set("cloudfunctionsRestrictedState",1)
  order.set("webhookAccessState",2)
  order.set("webhookIngressState",3)
  order.set("serviceDirectoryWebhookState",4)
  var counter = 1
  const map = new ReversibleMap({})
  for (const x0 of [true, false]) { 
    for (const x1 of [true, false]) { 
      for (const x2 of [true, false]) { 
        for (const x3 of [true, false]) { 
          for (const x4 of [true, false]) { 
            const curr_array = [x0, x1, x2, x3, x4]
            map.set(counter, curr_array)
            counter += 1;
          }
        }
      }
    }
  }
  const stateCache = [null, null, null, null, null]
  return {map: map, order: order, stateCache:stateCache}
}

function getState() {
  return {
    'status': {current: null, set: null},
    'isUpdating': {current: null, set: null},
    'blocked': {current: null, set: null},
    'timeSinceSliderClick': {current: null, set: null},
  }
}
function InitializeState(state) {
  [state.isUpdating.current, state.isUpdating.set] = useState(true);
  [state.status.current, state.status.set] = useState(false);
  [state.blocked.current, state.blocked.set] = useState(false);
  [state.timeSinceSliderClick.current, state.timeSinceSliderClick.set] = useState(1000*TIMER_SCALE);
}

function ProjectData () {
  const project_id = {current: null, set: null};
  const principal = {current: null, set: null};
  const webhook_name = {current: null, set: null};
  const region = {current: null, set: null};
  const accessPolicyTitle = {current: null, set: null};
  [project_id.current, project_id.set] = useState(project_id_default);
  [webhook_name.current, webhook_name.set] = useState(webhook_name_default);
  [region.current, region.set] = useState(region_default);
  [principal.current, principal.set] = useState(null);
  [accessPolicyTitle.current, accessPolicyTitle.set] = useState(access_policy_title_default);
  return {
    project_id: project_id,
    webhook_name: webhook_name,
    region: region,
    principal: principal,
    accessPolicyTitle: accessPolicyTitle,
  }
}

function AssetStatus() {
  const dialogflowService = {current: null, set: null};
  const cloudfunctionService = {current: null, set: null};
  const computeService = {current: null, set: null};
  const iamService = {current: null, set: null};
  const servicedirectoryService = {current: null, set: null};
  const runService = {current: null, set: null};
  const cloudbuildService = {current: null, set: null};
  const artifactregistryService = {current: null, set: null};
  const accesscontextmanagerService = {current: null, set: null};
  const vpcaccessService = {current: null, set: null};
  const appengineService = {current: null, set: null};
  const cloudbillingService = {current: null, set: null};
  const network = {current: null, set: null};
  const subNetwork = {current: null, set: null};
  const natRouter = {current: null, set: null};
  const natManual = {current: null, set: null};
  const firewallDialogflow = {current: null, set: null};
  const firewallAllow = {current: null, set: null};
  const proxyNamespace = {current: null, set:null};
  const proxyService = {current: null, set:null};
  const proxyEndpoint = {current: null, set:null};
  const proxyAddress = {current: null, set:null};
  const networkModule = {current: null, set:null};
  const servicesModule = {current: null, set:null};
  const serviceDirectoryModule = {current: null, set:null};
  const webhookAgentModule = {current: null, set:null};
  const storageBucket = {current: null, set:null};
  const webhookArchive = {current: null, set:null};
  const webhookFunction = {current: null, set:null};
  const webhookAgent = {current: null, set:null};
  const allAssets = {current: null, set:null};
  const servicePerimeterModule = {current: null, set:null};
  // const accessPolicy = {current: null, set:null};
  const servicePerimeter = {current: null, set:null};

  
  
  


  [cloudfunctionService.current, cloudfunctionService.set] = useState(null);
  [dialogflowService.current, dialogflowService.set] = useState(null);
  [computeService.current, computeService.set] = useState(null); 
  [iamService.current, iamService.set] = useState(null); 
  [servicedirectoryService.current, servicedirectoryService.set] = useState(null); 
  [runService.current, runService.set] = useState(null); 
  [cloudbuildService.current, cloudbuildService.set] = useState(null); 
  [artifactregistryService.current, artifactregistryService.set] = useState(null); 
  [accesscontextmanagerService.current, accesscontextmanagerService.set] = useState(null); 
  [vpcaccessService.current, vpcaccessService.set] = useState(null); 
  [appengineService.current, appengineService.set] = useState(null); 
  [cloudbillingService.current, cloudbillingService.set] = useState(null); 
  [network.current, network.set] = useState(null);
  [subNetwork.current, subNetwork.set] = useState(null);
  [natRouter.current, natRouter.set] = useState(null);
  [natManual.current, natManual.set] = useState(null);
  [firewallDialogflow.current, firewallDialogflow.set] = useState(null);
  [firewallAllow.current, firewallAllow.set] = useState(null);
  [proxyNamespace.current, proxyNamespace.set] = useState(null);
  [proxyService.current, proxyService.set] = useState(null);
  [proxyEndpoint.current, proxyEndpoint.set] = useState(null);
  [proxyAddress.current, proxyAddress.set] = useState(null);
  [networkModule.current, networkModule.set] = useState(null);
  [servicesModule.current, servicesModule.set] = useState(null);
  [serviceDirectoryModule.current, serviceDirectoryModule.set] = useState(null);
  [webhookAgentModule.current, webhookAgentModule.set] = useState(null);
  [storageBucket.current, storageBucket.set] = useState(null);
  [webhookArchive.current, webhookArchive.set] = useState(null);
  [webhookFunction.current, webhookFunction.set] = useState(null);
  [webhookAgent.current, webhookAgent.set] = useState(null);
  [allAssets.current, allAssets.set] = useState(null);
  [servicePerimeterModule.current, servicePerimeterModule.set] = useState(null);
  // [accessPolicy.current, accessPolicy.set] = useState(null);
  [servicePerimeter.current, servicePerimeter.set] = useState(null);


  return {
    "module.services": servicesModule,
    "google_project_service.cloudfunctions": cloudfunctionService,
    "google_project_service.dialogflow": dialogflowService,
    "google_project_service.compute": computeService,
    "module.services.google_project_service.iam": iamService,
    "google_project_service.servicedirectory": servicedirectoryService,
    "module.services.google_project_service.run": runService,
    "google_project_service.cloudbuild": cloudbuildService,
    "module.services.google_project_service.artifactregistry": artifactregistryService,
    "google_project_service.accesscontextmanager": accesscontextmanagerService,
    "google_project_service.cloudbilling": cloudbillingService,
    "module.services.google_project_service.vpcaccess": vpcaccessService,
    "module.services.google_project_service.appengine": appengineService,
    "module.vpc_network": networkModule,
    "module.vpc_network.google_compute_network.vpc_network": network,
    "module.vpc_network.google_compute_subnetwork.reverse_proxy_subnetwork": subNetwork,
    "module.vpc_network.google_compute_router.nat_router": natRouter,
    "module.vpc_network.google_compute_router_nat.nat_manual": natManual,
    "module.vpc_network.google_compute_firewall.allow_dialogflow": firewallDialogflow,
    "module.vpc_network.google_compute_firewall.allow": firewallAllow,
    "module.vpc_network.google_compute_address.reverse_proxy_address": proxyAddress,
    "module.service_directory": serviceDirectoryModule,
    "module.service_directory.google_service_directory_namespace.reverse_proxy": proxyNamespace,
    "module.service_directory.google_service_directory_service.reverse_proxy": proxyService,
    "module.service_directory.google_service_directory_endpoint.reverse_proxy": proxyEndpoint,
    "module.webhook_agent": webhookAgentModule,
    "module.webhook_agent.google_storage_bucket.bucket": storageBucket,
    "module.webhook_agent.google_storage_bucket_object.archive": webhookArchive,
    "module.webhook_agent.google_cloudfunctions_function.webhook": webhookFunction,
    "module.webhook_agent.google_dialogflow_cx_agent.full_agent": webhookAgent,
    "module.service_perimeter": servicePerimeterModule,
    // "module.service_perimeter.google_access_context_manager_access_policy.access-policy":accessPolicy,
    "module.service_perimeter.google_access_context_manager_service_perimeter.service-perimeter":servicePerimeter,
    "all": allAssets,
  }

  

}

function DataModel () {
  const pageMapper = BuildMapPageNumberToState();
  const loggedIn = {current: null, set: null};
  const pageNumber = {current: null, set: null};
  const renderedPageNumber = {current: null, set: null};
  const activePage = {current: null, set: null};
  const terraformLocked = {current: null, set: null};
  const validProjectId = {current: null, set: null};
  const invertAssetCollectionSwitches = {current: null, set: null};
  const showServicesPanel = {current: null, set: null};
  const sessionExpiredModalOpen = {current: null, set: null};

  const allStates = {};
  allStates["dialogflowRestrictedState"] = getState();
  allStates["cloudfunctionsRestrictedState"] = getState();
  allStates["webhookAccessState"] = getState();
  allStates["webhookIngressState"] = getState();
  allStates["serviceDirectoryWebhookState"] = getState();
  InitializeState(allStates["dialogflowRestrictedState"]);
  InitializeState(allStates["cloudfunctionsRestrictedState"]);
  InitializeState(allStates["webhookAccessState"]);
  InitializeState(allStates["webhookIngressState"]);
  InitializeState(allStates["serviceDirectoryWebhookState"]);

  [loggedIn.current, loggedIn.set] = useState(false);
  [pageNumber.current, pageNumber.set] = useState(33);
  [renderedPageNumber.current, renderedPageNumber.set] = useState(null);
  [activePage.current, activePage.set] = useState(0);
  [terraformLocked.current, terraformLocked.set] = useState(false);
  [validProjectId.current, validProjectId.set] = useState(false);
  [invertAssetCollectionSwitches.current, invertAssetCollectionSwitches.set] = useState(false);
  [showServicesPanel.current, showServicesPanel.set] = useState(true);
  [sessionExpiredModalOpen.current, sessionExpiredModalOpen.set] = useState(false);

  const dataModel = {
    pageMapper: pageMapper,
    loggedIn: loggedIn,
    pageNumber: pageNumber,
    activePage: activePage,
    allStates: allStates,
    renderedPageNumber: renderedPageNumber,
    projectData: ProjectData(),
    assetStatus: AssetStatus(),
    terraformLocked:terraformLocked,
    validProjectId:validProjectId,
    invertAssetCollectionSwitches:invertAssetCollectionSwitches,
    showServicesPanel:showServicesPanel,
    sessionExpiredModalOpen:sessionExpiredModalOpen,
  }
  return dataModel
}

function getPage(allStates, pageMapper) {
  const curr_array = [null, null, null, null, null]
  for (const [key, value] of Object.entries(allStates)) {
    const idx = pageMapper.order.get(key)
    curr_array[idx] = value.status.current
  }
  for (var ii = 0; ii < curr_array.length; ii++) {
    if (curr_array[ii] !== "BLOCKED") {
      pageMapper.stateCache[ii] = curr_array[ii]
    }
  }
  return pageMapper.map.get(pageMapper.stateCache)
}

export {DataModel, getPage, webhook_name_default}