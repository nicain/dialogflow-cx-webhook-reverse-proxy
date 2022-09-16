import {useState} from "react";
import {TIMER_SCALE} from "./StatusPollToggle.js"

const project_id_default = "vpc-sc-demo-nicholascain14";
const webhook_name_default = "custom-telco-webhook";
const region_default = "us-central1";

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
  [project_id.current, project_id.set] = useState(project_id_default);
  [webhook_name.current, webhook_name.set] = useState(webhook_name_default);
  [region.current, region.set] = useState(region_default);
  [principal.current, principal.set] = useState(null);

  return {
    project_id: project_id,
    webhook_name: webhook_name,
    region: region,
    principal: principal,
  }
}

function DataModel () {
  const pageMapper = BuildMapPageNumberToState();
  const loggedIn = {current: null, set: null};
  const pageNumber = {current: null, set: null};
  const renderedPageNumber = {current: null, set: null};
  const activePage = {current: null, set: null};

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

  const dataModel = {
    pageMapper: pageMapper,
    loggedIn: loggedIn,
    pageNumber: pageNumber,
    activePage: activePage,
    allStates: allStates,
    renderedPageNumber: renderedPageNumber,
    projectData: ProjectData(),
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