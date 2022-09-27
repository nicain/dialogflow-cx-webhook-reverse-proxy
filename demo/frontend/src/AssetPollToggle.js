import React,  {useEffect, useRef} from "react";
import Switch from '@mui/material/Switch';
import Typography from '@mui/material/Typography';
import {QueryClient, QueryClientProvider, useQuery } from "react-query";
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

function AlertDialog(props) {
  return (
      <Dialog
      open={props.open}
      onClose={props.onClickCancel}
      aria-labelledby="alert-dialog-title"
      aria-describedby="alert-dialog-description"
    >
      <DialogTitle id="alert-dialog-title">
        {`Destroy Terraform Resourse ${props.target}?`}
      </DialogTitle>
      <DialogContent>
        <DialogContentText id="alert-dialog-description">
          {`Removing ${props.name} might delete resources, and cannot be reversed. Continue?`}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={props.onClickCancel} variant='contained' autoFocus>Cancel</Button>
        <Button onClick={props.onClickDestroy} variant='contained' color="error" >Destroy</Button>
      </DialogActions>
    </Dialog>
  );
}

// 

function ErrorDialog(props) {

  if (props.error && props.error.response.data.errors[0]==="Error: Error acquiring the state lock") {
    console.log("Error acquiring the state lock")
  } else if (props.error) {
    if (props.target==="google_compute_router_nat.nat_manual") {
      props.setResourceName(`'projects/${props.dataModel.projectData.project_id.current}/regions/${props.dataModel.projectData.region.current}/routers/nat-router/nat-config'`)
    } else if (props.target==="google_service_directory_service.reverse_proxy") {
      props.setResourceName(`'projects/${props.dataModel.projectData.project_id.current}/locations/${props.dataModel.projectData.region.current}/namespaces/df-namespace/services/df-service'`)
    } else if (props.target==="google_service_directory_endpoint.reverse_proxy") {
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
  const [alertBoxOpen, setAlertBoxOpen] = React.useState(false);
  const [errorBoxOpen, setErrorBoxOpen] = React.useState(false);
  const [resourceName, setResourceName] = React.useState(null);
  const completed = useRef(false);

  const handleErrorBoxCancel = () => {
    setErrorBoxOpen(false);
  }

  const handleAlertBoxClose = () => {
    setAlertBoxOpen(false);
  };
  
  const handleAlertBoxDestroy = () => {
    setAlertBoxOpen(false);
    update.refetch();
  }

  function onSettled() {
    props.dataModel.terraformLocked.set(false);
    completed.current = true;
  }

  function queryFunction () {
    props.dataModel.terraformLocked.set(true);
    return axios.post("/update_target", 
      {
        "targets":[props.target],
        "destroy": asset.current === true ? true : false,
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
        asset.set(update.data.resources.includes(props.target))
      }
    }
  })

  function onChange() {
    if (asset.current && props.enableAlert) {
      setAlertBoxOpen(true);
    } else {
      update.refetch()
    }
  }

  var indicator
  if (update.isFetching || tfImport.isFetching || typeof(asset.current) != "boolean") {

    if (asset.current==='BLOCKED') {
      indicator =
          <Switch
            checked={typeof(asset.current) == "boolean" ? asset.current : false}
            color="primary"
            style={{visibility: "hidden"}}
          />
    } else {
      indicator = <CircularProgress size={20}/>
    }
  } else {
    indicator = <Switch
      onChange={onChange} 
      checked={typeof(asset.current) == "boolean" ? asset.current : false}
      color="primary"
      style={{visibility: props.dataModel.terraformLocked.current ? "hidden" : "visible"}}
    />
  }

  var name
  if (props.dataModel && props.dataModel.projectData.project_id.current != null) {
    name = "Foo"//<Typography>{props.name}</Typography>;
    name = <Link target="_blank" href={`https://console.cloud.google.com/apis/library/${props.name}?project=${props.dataModel.projectData.project_id.current}`} variant="body1">{props.name}</Link>
  } else {
    name = <Typography variant="body2">{props.name}</Typography>;
  }

  return (
    <>
      <AlertDialog 
        open={alertBoxOpen} 
        onClickCancel={handleAlertBoxClose} 
        onClickDestroy={handleAlertBoxDestroy} 
        target={props.target}
        name={props.name}
      />
      <ErrorDialog 
        open={errorBoxOpen} 
        onClickCancel={handleErrorBoxCancel}
        onClickImport={handleErrorBoxImport}
        target={props.target}
        setResourceName={setResourceName}
        error={update.error}
        dataModel={props.dataModel}/>
      <Grid container item direction='row' columnSpacing={3} justifyContent="flex-start" alignItems="center">
        <Box sx={{ pl:1, mx:0, my: .5, py:1, width: 300, height: 30  }}         
          display="flex" 
          alignItems="center"
          justifyContent="right">
          {name}
        </Box>
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
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <ToggleAsset name={props.name} target={props.target} dataModel={props.dataModel} enableAlert={props.enableAlert}/>
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


// function TogglePollAsset (props) {
//   return (
//     <div>
//       <QueryToggleAsset name={props.name} target={props.target} asset={props.asset} dataModel={props.dataModel} enableAlert={props.enableAlert}/>
//       <QueryPollAssetStatus name={props.name} target={props.target} asset={props.asset} dataModel={props.dataModel}/>
//     </div>
//   )
// }


function ServicesPanel (props) {
  return (
    <>
      <Typography variant="h6">
        APIs & Services:
      </Typography>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="dialogflow.googleapis.com" target="google_project_service.dialogflow" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="cloudfunctions.googleapis.com" target="google_project_service.cloudfunctions" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="compute.googleapis.com" target="google_project_service.compute" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="iam.googleapis.com" target="google_project_service.iam" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="servicedirectory.googleapis.com" target="google_project_service.servicedirectory" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="run.googleapis.com" target="google_project_service.run" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="cloudbuild.googleapis.com" target="google_project_service.cloudbuild" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="artifactregistry.googleapis.com" target="google_project_service.artifactregistry" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="accesscontextmanager.googleapis.com" target="google_project_service.accesscontextmanager" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="vpcaccess.googleapis.com" target="google_project_service.vpcaccess" dataModel={props.dataModel} enableAlert={true}/>
        <QueryToggleAsset name="appengine.googleapis.com" target="google_project_service.appengine" dataModel={props.dataModel} enableAlert={true}/>
      </Grid>
    </>
  )
}

function NetworkPanel (props) {
  return (
    <>
      <Typography variant="h6">
        VPC Resources:
      </Typography>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="VPC network" target="google_compute_network.vpc_network" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="VPC subnetwork" target="google_compute_subnetwork.reverse_proxy_subnetwork" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Router" target="google_compute_router.nat_router" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Router NAT" target="google_compute_router_nat.nat_manual" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Firewall: Allow General" target="google_compute_firewall.allow_dialogflow" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Firewall: Allow Dialogflow" target="google_compute_firewall.allow" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Address" target="google_compute_address.reverse_proxy_address" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
      <Divider sx={{ my:0 }} orientation="horizontal" flexItem/>
      <Typography variant="h6">
        Proxy Service:
      </Typography>
      <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="Namespace" target="google_service_directory_namespace.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Service" target="google_service_directory_service.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Endpoint" target="google_service_directory_endpoint.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
      </Grid>
    </>
  )
}

function AgentPanel (props) {
  return (
    <>
      <Typography variant="h6">
        Webhook Agent:
      </Typography>
      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      {/* <Grid container  justifyContent="flex-end">
        <QueryToggleAsset name="Namespace" target="google_service_directory_namespace.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Service" target="google_service_directory_service.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
        <QueryToggleAsset name="Endpoint" target="google_service_directory_endpoint.reverse_proxy" dataModel={props.dataModel} enableAlert={false}/>
      </Grid> */}
    </>
  )
}






export {ServicesPanel, NetworkPanel, AgentPanel, QueryPollAssetStatus}












// google_storage_bucket.bucket
// google_storage_bucket_object.archive
// google_cloudfunctions_function.webhook
// google_dialogflow_cx_agent.full_agent