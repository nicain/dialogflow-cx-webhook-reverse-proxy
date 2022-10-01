import React,  {useEffect, useRef} from "react";
import Switch from '@mui/material/Switch';
import Typography from '@mui/material/Typography';
import {QueryClient, QueryClientProvider, useQuery, useQueryErrorResetBoundary } from "react-query";
import axios from "axios";
import CircularProgress from '@mui/material/CircularProgress';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import Button from '@mui/material/Button';
import Link from '@mui/material/Link';
import Tooltip from '@mui/material/Tooltip';
import Divider from '@mui/material/Divider';
import Alert from '@mui/material/Alert';
import { backendEnabled } from './Utilities.js';

const PANEL_WIDTH = 150;

function ResourceCollectionDeployment(target, dataModel) {
  var valueList
  if (target==="module.webhook_agent") {
    valueList = [
      dataModel.assetStatus["module.webhook_agent.google_storage_bucket.bucket"].current===true ? 1 : 0,
      dataModel.assetStatus["module.webhook_agent.google_storage_bucket_object.archive"].current===true ? 1 : 0,
      dataModel.assetStatus["module.webhook_agent.google_cloudfunctions_function.webhook"].current===true ? 1 : 0,
      dataModel.assetStatus["module.webhook_agent.google_dialogflow_cx_agent.full_agent"].current===true ? 1 : 0,
    ]
  } else if (target==="module.service_directory") {
    valueList = [
      dataModel.assetStatus["module.service_directory.google_service_directory_namespace.reverse_proxy"].current===true ? 1 : 0,
      dataModel.assetStatus["module.service_directory.google_service_directory_service.reverse_proxy"].current===true ? 1 : 0,
      dataModel.assetStatus["module.service_directory.google_service_directory_endpoint.reverse_proxy"].current===true ? 1 : 0,
    ]
  } else if (target==="module.vpc_network") {
    valueList = [
      dataModel.assetStatus["module.vpc_network.google_compute_network.vpc_network"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_subnetwork.reverse_proxy_subnetwork"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_router.nat_router"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_router_nat.nat_manual"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_firewall.allow_dialogflow"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_firewall.allow"].current===true ? 1 : 0,
      dataModel.assetStatus["module.vpc_network.google_compute_address.reverse_proxy_address"].current===true ? 1 : 0,
    ]
  } else if (target==="module.services") {
    valueList = [
      dataModel.assetStatus["google_project_service.dialogflow"].current===true ? 1 : 0,
      dataModel.assetStatus["google_project_service.cloudfunctions"].current===true ? 1 : 0,
      dataModel.assetStatus["google_project_service.compute"].current===true ? 1 : 0,
      dataModel.assetStatus["module.services.google_project_service.iam"].current===true ? 1 : 0,
      dataModel.assetStatus["google_project_service.servicedirectory"].current===true ? 1 : 0,
      dataModel.assetStatus["module.services.google_project_service.run"].current===true ? 1 : 0,
      dataModel.assetStatus["google_project_service.cloudbuild"].current===true ? 1 : 0,
      dataModel.assetStatus["module.services.google_project_service.artifactregistry"].current===true ? 1 : 0,
      dataModel.assetStatus["google_project_service.accesscontextmanager"].current===true ? 1 : 0,
      dataModel.assetStatus["module.services.google_project_service.vpcaccess"].current===true ? 1 : 0,
      dataModel.assetStatus["module.services.google_project_service.appengine"].current===true ? 1 : 0,
    ]
  } else if (target==="module.service_perimeter") {
    valueList = [
      dataModel.assetStatus["module.service_perimeter.google_access_context_manager_access_policy.access-policy"].current===true ? 1 : 0,
      dataModel.assetStatus["module.service_perimeter.google_access_context_manager_service_perimeter.service-perimeter"].current===true ? 1 : 0,
    ]
  }
  return {
    deployed: valueList.reduce((a, b) => a + b, 0),
    count: valueList.length,
  }
}

function ResourceCollectionIsAllSame(target, dataModel) {
  const modules = ["module.webhook_agent", "module.service_directory", "module.vpc_network", "module.services", "module.service_perimeter"];
  if (modules.includes(target)) {
    const deployment = ResourceCollectionDeployment(target, dataModel)
    return (deployment['deployed'] === 0) || (deployment['count'] === deployment['deployed'])
  } else if (target === "all") {
    var count = 0
    var deployed = 0
    for (const module of modules) {
      const deployment = ResourceCollectionDeployment(module, dataModel)
      count += deployment['count']
      deployed += deployment['deployed']
    }
    return (deployed === 0) || (deployed === count)
  }
}

// function AlertDialog(props) {
//   return (
//       <Dialog
//       open={props.open}
//       onClose={props.onClickCancel}
//       aria-labelledby="alert-dialog-title"
//       aria-describedby="alert-dialog-description"
//     >
//       <DialogTitle id="alert-dialog-title">
//         {`Destroy Terraform Resourse ${props.target}?`}
//       </DialogTitle>
//       <DialogContent>
//         <DialogContentText id="alert-dialog-description">
//           {`Removing ${props.name} might delete resources, and cannot be reversed. Continue?`}
//         </DialogContentText>
//       </DialogContent>
//       <DialogActions>
//         <Button onClick={props.onClickCancel} variant='contained' autoFocus>Cancel</Button>
//         <Button onClick={props.onClickDestroy} variant='contained' color="error" >Destroy</Button>
//       </DialogActions>
//     </Dialog>
//   );
// }


function ErrorDialog(props) {

  if (props.error && props.error.response.data.errors[0]==="Error: Error acquiring the state lock") {
    console.log("Error acquiring the state lock")
  } else if (props.error) {
    if (props.target==="module.vpc_network.google_compute_router_nat.nat_manual") {
      props.setResourceName(`'projects/${props.dataModel.projectData.project_id.current}/regions/${props.dataModel.projectData.region.current}/routers/nat-router/nat-config'`)
    } else if (props.target==="module.service_directory.google_service_directory_service.reverse_proxy") {
      props.setResourceName(`'projects/${props.dataModel.projectData.project_id.current}/locations/${props.dataModel.projectData.region.current}/namespaces/df-namespace/services/df-service'`)
    } else if (props.target==="module.service_directory.google_service_directory_endpoint.reverse_proxy") {
      props.setResourceName(`'projects/${props.dataModel.projectData.project_id.current}/locations/${props.dataModel.projectData.region.current}/namespaces/df-namespace/services/df-service/endpoints/df-endpoint'`)
    } else {
      props.setResourceName(props.error.response.data.errors[0]["diagnostic"]["summary"])
    }
    return (
        <Dialog
        open={props.open}
        onClose={() => {}}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle>
          {`Error Encountered when deploying ${props.target}`} 
        </DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {props.error.response.data.errors[0]["@message"]}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={props.onClickCancel} variant='contained'>Cancel</Button>
          <Button onClick={props.onClickImport} variant='contained' autoFocus>Import</Button>
        </DialogActions>
      </Dialog>
    );
  } else {
    return <></>
  }
}




function ToggleAsset(props) {
  const asset = props.dataModel.assetStatus[props.target]
  // const [alertBoxOpen, setAlertBoxOpen] = React.useState(false);
  const [errorBoxOpen, setErrorBoxOpen] = React.useState(false);
  const [resourceName, setResourceName] = React.useState(null);
  const completed = useRef(false);

  const handleErrorBoxCancel = () => {
    setErrorBoxOpen(false);
  }

  // const handleAlertBoxClose = () => {
  //   setAlertBoxOpen(false);
  // };
  
  // const handleAlertBoxDestroy = () => {
  //   setAlertBoxOpen(false);
  //   update.refetch();
  // }

  function onSettled() {
    props.dataModel.terraformLocked.set(false);
    completed.current = true;
    props.dataModel.invertAssetCollectionSwitches.set(false)
  }

  
  function queryFunction () {
    var destroy = asset.current === true ? true : false
    if (props.isModuleSwitch && props.dataModel.invertAssetCollectionSwitches.current  && !ResourceCollectionIsAllSame(props.target, props.dataModel)) {
      destroy = !destroy
    }

    var target;
    if (props.target==="module.services" && destroy) {
      target = [
        props.target, 
        "google_project_service.dialogflow", 
        "google_project_service.cloudfunctions",
        "google_project_service.compute",
        "google_project_service.servicedirectory",
        "google_project_service.cloudbuild",
        "google_project_service.accesscontextmanager",
      ];
    } else {
      target = [props.target]
    }

    props.dataModel.terraformLocked.set(true);
    return axios.post("/update_target", 
      {
        "targets":target,
        "destroy": destroy,
      }, 
      {params: 
        {
        project_id:props.dataModel.projectData.project_id.current,
        // debug: true,
        }
      }
    ).then((res) => res.data)
  }

  function onError (error) {
    setErrorBoxOpen(true)
  }

  function importFunction () {
    props.dataModel.terraformLocked.set(true);
    return axios.post("/import", 
      {
        resourceName: resourceName
      }, 
      {params: 
        {
        project_id:props.dataModel.projectData.project_id.current,
        target:props.target,
        }
      }
    ).then((res) => res.data)
  }
  
  const update = useQuery("/update_target", queryFunction, 
    {
      enabled:false, 
      onSettled: onSettled,
      retry:0,
      onError: onError,
    }
  )

  function onImportSuccess() {
    update.refetch() 
  }

  const tfImport = useQuery(["/import"], importFunction, 
    {
      enabled:false,
      onSettled: onSettled, 
      retry:0,
      onSuccess: onImportSuccess,
    }
  )

  const handleErrorBoxImport = () => {
    setErrorBoxOpen(false);
    tfImport.refetch()
  }

  useEffect(() => {
    if (update.data && completed.current){ 
      if (update.data.status==='BLOCKED') {
        console.log(update.data.reason)
      } else {
        completed.current = false;
        for (var key in props.dataModel.assetStatus) {
          props.dataModel.assetStatus[key].set(update.data.resources.includes(key))
        }
      }
    }
  })

  function onChange() {
    var destroy = asset.current === true ? true : false
    if (props.isModuleSwitch && props.dataModel.invertAssetCollectionSwitches.current  && !ResourceCollectionIsAllSame(props.target, props.dataModel)) {
      destroy = !destroy
    }
    // if (destroy && props.enableAlert) {
    //   setAlertBoxOpen(true);
    // } else {
    //   update.refetch()
    // }
    update.refetch()
  }


  var visibility
  if (!props.dataModel.validProjectId.current || update.isFetching || tfImport.isFetching || typeof(asset.current) != "boolean" || props.dataModel.terraformLocked.current || asset.current==='BLOCKED') {
    visibility = "hidden"
  } else {
    visibility = "visible"
  }


  var checked = typeof(asset.current) == "boolean" ? asset.current : false
  if (props.isModuleSwitch && props.dataModel.invertAssetCollectionSwitches.current && !ResourceCollectionIsAllSame(props.target, props.dataModel)) {
    checked = !checked
  }
  const indicator = <Switch
    onChange={onChange} 
    checked={checked}
    color="primary"
    style={{visibility: visibility}}
    size={props.target==="all" ? "medium" : "small"}
  />

  var name
  if (props.dataModel && props.dataModel.projectData.project_id.current != null) {
    name = "Foo"//<Typography>{props.name}</Typography>;
    name = <Link target="_blank" href={`https://console.cloud.google.com/apis/library/${props.name}?project=${props.dataModel.projectData.project_id.current}`} variant="body1">{props.name}</Link>
  } else {
    name = <Typography variant="body2">{props.name}</Typography>;
  }

  var nameBox = (        
    <Box sx={{ pl:1, mx:0, my: .5, py:1, width: PANEL_WIDTH, height: 30  }}         
      display="flex" 
      alignItems="center"
      justifyContent="right">
      {name}
    </Box>
  )

  return (
    <>
      {/* <AlertDialog 
        open={alertBoxOpen} 
        onClickCancel={handleAlertBoxClose} 
        onClickDestroy={handleAlertBoxDestroy} 
        target={props.target}
        name={props.name}
      /> */}
      <ErrorDialog 
        open={errorBoxOpen} 
        onClickCancel={handleErrorBoxCancel}
        onClickImport={handleErrorBoxImport}
        target={props.target}
        setResourceName={setResourceName}
        error={update.error}
        dataModel={props.dataModel}/>
      <Grid container item direction='row' columnSpacing={3} justifyContent="flex-start" alignItems="center">
        {props.includeNameBox? <></>: nameBox}
        <Box sx={{ width: 60, height: 30  }}         
          display="flex" 
          alignItems="center"
          justifyContent="center">
          {indicator}
        </Box>
      </Grid>
    </>
  )
}




function PollAssetStatus(props) {
  const completed = useRef(false);

  function onSettled() {
    props.dataModel.terraformLocked.set(false);
    completed.current = true;
  }

  function queryFunction () {
    props.dataModel.terraformLocked.set(true);
    return axios
    .get('/asset_status', {params: {
      project_id:props.dataModel.projectData.project_id.current,
      // debug: true,
  }})
    .then((res) => res.data)
  }

  const {data} = useQuery(
    ["/asset_status", props.dataModel.projectData.project_id.current], queryFunction,
    {
      refetchInterval: (props.dataModel.terraformLocked.current? false : 600000),
      onSettled: onSettled,
      retry: false,
      enabled: backendEnabled(props.dataModel),
    }
  );

  useEffect(() => {
    if (data && completed.current){
      if (data.status==='BLOCKED') {
        console.log(data.reason)
      } else {
        completed.current = false;
        for (var key in props.dataModel.assetStatus) {
          props.dataModel.assetStatus[key].set(data.resources.includes(key))
        }
      }
    }
  })
  return <></>
}


function QueryToggleAsset(props) {
  const queryClient = new QueryClient();
  const {isModuleSwitch=false} = props;
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <ToggleAsset name={props.name} target={props.target} dataModel={props.dataModel} enableAlert={props.enableAlert} includeNameBox={props.includeNameBox} isModuleSwitch={isModuleSwitch}/>
      </QueryClientProvider>
    </div>
  )
}


function QueryPollAssetStatus (props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <PollAssetStatus dataModel={props.dataModel}/>
      </QueryClientProvider>
    </div>
  )
}


function ServicesPanel (props) {
  return (
    <>
      <Grid container direction='row' justifyContent="space-between">
        <Typography variant="h6">
          APIs & Services:
        </Typography> 
        <QueryToggleAsset target="module.services" dataModel={props.dataModel} enableAlert={true} includeNameBox={true} isModuleSwitch={true}/>
      </Grid>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="dialogflow" target="google_project_service.dialogflow" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="cloudfunctions" target="google_project_service.cloudfunctions" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="compute" target="google_project_service.compute" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="iam" target="module.services.google_project_service.iam" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="servicedirectory" target="google_project_service.servicedirectory" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="run" target="module.services.google_project_service.run" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="cloudbuild" target="google_project_service.cloudbuild" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="artifactregistry" target="module.services.google_project_service.artifactregistry" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="accesscontextmanager" target="google_project_service.accesscontextmanager" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="vpcaccess" target="module.services.google_project_service.vpcaccess" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="appengine" target="module.services.google_project_service.appengine" dataModel={props.dataModel} enableAlert={true}/>
      </Grid>
    </>
  )
}

function NetworkPanel (props) {
  return (
    <>
      <Grid container direction='row' justifyContent="space-between">
        <Typography variant="h6">
          VPC Resources:
        </Typography> 
        <QueryToggleAsset target="module.vpc_network" dataModel={props.dataModel} enableAlert={false} includeNameBox={true} isModuleSwitch={true}/>
      </Grid>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="VPC network" target="module.vpc_network.google_compute_network.vpc_network" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="VPC subnetwork" target="module.vpc_network.google_compute_subnetwork.reverse_proxy_subnetwork" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Router" target="module.vpc_network.google_compute_router.nat_router" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Router NAT" target="module.vpc_network.google_compute_router_nat.nat_manual" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Firewall: General" target="module.vpc_network.google_compute_firewall.allow_dialogflow" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Firewall: Dialogflow" target="module.vpc_network.google_compute_firewall.allow" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Address" target="module.vpc_network.google_compute_address.reverse_proxy_address" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
    </>
  )
}


function ServiceDirectoryPanel (props) {
  return (
    <>
      <Grid container direction='row' justifyContent="space-between">
        <Typography variant="h6">
        Service Directory:
        </Typography> 
        <QueryToggleAsset target="module.service_directory" dataModel={props.dataModel} enableAlert={false} includeNameBox={true} isModuleSwitch={true}/>
      </Grid>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="Namespace" target="module.service_directory.google_service_directory_namespace.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Service" target="module.service_directory.google_service_directory_service.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Endpoint" target="module.service_directory.google_service_directory_endpoint.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
    </>
  )
}

function AgentPanel (props) {
  return (
    <>
      <Grid container direction='row' justifyContent="space-between">
        <Typography variant="h6">
        Webhook Agent:
        </Typography> 
        <QueryToggleAsset target="module.webhook_agent" dataModel={props.dataModel} enableAlert={false} includeNameBox={true} isModuleSwitch={true}/>
      </Grid>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="Storage Bucket" target="module.webhook_agent.google_storage_bucket.bucket" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Webhook Source Code" target="module.webhook_agent.google_storage_bucket_object.archive" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Webhook Function" target="module.webhook_agent.google_cloudfunctions_function.webhook" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Dialogflow Agent" target="module.webhook_agent.google_dialogflow_cx_agent.full_agent" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
    </>
  )
}





function ServicePerimeterPanel (props) {
  return (
    <>
      <Grid container direction='row' justifyContent="space-between">
        <Typography variant="h6">
        Service Perimeter:
        </Typography> 
        <QueryToggleAsset target="module.service_perimeter" dataModel={props.dataModel} enableAlert={false} includeNameBox={true} isModuleSwitch={true}/>
      </Grid>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="Access Policy" target="module.service_perimeter.google_access_context_manager_access_policy.access-policy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Service Perimeter" target="module.service_perimeter.google_access_context_manager_service_perimeter.service-perimeter" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
    </>
  )
}

export {ServicesPanel, NetworkPanel, AgentPanel, QueryPollAssetStatus, QueryToggleAsset, ServiceDirectoryPanel, ServicePerimeterPanel, PANEL_WIDTH}
