import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import { styled } from "@mui/material/styles";
import {ExecuteToggleStatus, QueryPollStatus, TIMER_SCALE} from "./StatusPollToggle.js"
import {StatusTutorialMode, ToggleStatusTutorialMode} from "./TutorialMode.js"
import {useState} from "react";
import Popover from '@mui/material/Popover';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Terminal from '@mui/icons-material/Terminal';


const Item = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  padding: 0,
  textAlign: "right",
  color: theme.palette.text.secondary,
}));



function getControlElem(title, state, timeout, blocked_by_timeout, queryEndpoint, toggleEndpoint, blocked_by, liveMode, dataModel, pageMapper, pageNumber) { 

  

  var statusElem
  var toggleStatusElem
  if (liveMode) {
    statusElem = <QueryPollStatus state={state} endpoint={queryEndpoint}  timeout={timeout*TIMER_SCALE} blocked_by={blocked_by} blocked_by_timeout={blocked_by_timeout*TIMER_SCALE} dataModel={dataModel}/>
    toggleStatusElem = <ExecuteToggleStatus state={state} endpoint={toggleEndpoint} timeout={timeout*TIMER_SCALE} blocked_by={blocked_by} blocked_by_timeout={blocked_by_timeout*TIMER_SCALE} dataModel={dataModel} pageMapper={pageMapper} pageNumber={pageNumber}/>
  } else {
    statusElem = <StatusTutorialMode state={state}/>
    toggleStatusElem = <ToggleStatusTutorialMode state={state}/>
  }

  return (
    <Grid container direction='row' columnSpacing={3} alignItems="center">
      <Grid item>
        <Item sx={{my: 0}} variant="string">{toggleStatusElem}</Item>
      </Grid>
      <Grid item sx={{ width: 320 }}>
        <Typography variant="body1" align="right">
          {title}
        </Typography> 
      </Grid>
      <Grid item>
        {statusElem}
      </Grid>
    </Grid>
  )
}

function StateChangeButtonGrid(props){  

  let webhookAccessState = props.dataModel.allStates.webhookAccessState
  let webhookIngressState = props.dataModel.allStates.webhookIngressState
  let cloudfunctionsRestrictedState = props.dataModel.allStates.cloudfunctionsRestrictedState
  let dialogflowRestrictedState = props.dataModel.allStates.dialogflowRestrictedState
  let serviceDirectoryWebhookState = props.dataModel.allStates.serviceDirectoryWebhookState
  let pageMapper = props.dataModel.pageMapper
  let pageNumber = props.dataModel.pageNumber
  let liveMode = props.liveMode
  let dataModel = props.dataModel

  return (
    <>
      <Grid container direction='column' rowSpacing={1}>
        {/* <Grid item>
          {getControlElem("Webhook Access Authenticated Only?",
            webhookAccessState, 3, 110,
            "/webhook_access_allow_unauthenticated_status", 
            "/update_webhook_access", 
            cloudfunctionsRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}
        </Grid>
        
        <Grid item>
        {getControlElem("Webhook Allow Internal Ingress Only?",
          webhookIngressState, 85, 110,
          "/webhook_ingress_internal_only_status", 
          "/update_webhook_ingress", 
          cloudfunctionsRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}
        </Grid> */}

        <Grid item>
        {getControlElem("Restrict Cloudfunctions Access to VPC?",
          cloudfunctionsRestrictedState, 15, null,
          "/restricted_services_status_cloudfunctions", 
          "/update_security_perimeter_cloudfunctions", 
          null, liveMode, dataModel, pageMapper, pageNumber)}
        </Grid>

        {/* <Grid item>
        {getControlElem("Restrict Dialogflow Access to VPC?",
          dialogflowRestrictedState, 15, null,
          "/restricted_services_status_dialogflow", 
          "/update_security_perimeter_dialogflow", 
          null, liveMode, dataModel, pageMapper, pageNumber)}
        </Grid> */}

        {/* <Grid item>
        {getControlElem("Route Dialogflow Through VPC Proxy?",
          serviceDirectoryWebhookState, 8, 110,
          "/service_directory_webhook_fulfillment_status", 
          "/update_service_directory_webhook_fulfillment", 
          dialogflowRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}
        </Grid> */}
      </Grid>
    </>
)}

export {StateChangeButtonGrid}