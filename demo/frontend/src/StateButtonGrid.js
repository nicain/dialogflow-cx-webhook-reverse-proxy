import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import { styled } from "@mui/material/styles";
import {ExecuteToggleStatus, QueryPollStatus, TIMER_SCALE} from "./StatusPollToggle.js"
import {StatusTutorialMode, ToggleStatusTutorialMode} from "./TutorialMode.js"

const Item = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  padding: 0,
  textAlign: "right",
  color: theme.palette.text.secondary,
}));

function getControlElem(title, state, timeout, blocked_by_timeout, queryEndpoint, toggleEndpoint, blocked_by, liveMode) { 

  var statusElem
  var toggleStatusElem
  if (liveMode) {
    statusElem = <QueryPollStatus state={state} endpoint={queryEndpoint}  timeout={timeout*TIMER_SCALE} blocked_by={blocked_by} blocked_by_timeout={blocked_by_timeout*TIMER_SCALE}/>
    toggleStatusElem = <ExecuteToggleStatus state={state} endpoint={toggleEndpoint} timeout={timeout*TIMER_SCALE} blocked_by={blocked_by} blocked_by_timeout={blocked_by_timeout*TIMER_SCALE}/>
  } else {
    statusElem = <StatusTutorialMode state={state}/>
    toggleStatusElem = <ToggleStatusTutorialMode state={state}/>
  }

  return (
  <Grid container item direction='row' columnSpacing={3} justifyContent="flex-start" alignItems="center">
  <Box sx={{ width: 270 }}>
    <Item sx={{my: 0}} variant="string">{title}</Item>
  </Box>
  <Box sx={{ width: 60 }}>
    <Item sx={{my: 0}} variant="string">{statusElem}</Item>
  </Box>
  <Item sx={{my: 0}} variant="string">{toggleStatusElem}</Item>
  </Grid>
)}

function StateChangeButtonGrid(props){  

  let webhookAccessState = props.dataModel.allStates.webhookAccessState
  let webhookIngressState = props.dataModel.allStates.webhookIngressState
  let cloudfunctionsRestrictedState = props.dataModel.allStates.cloudfunctionsRestrictedState
  let dialogflowRestrictedState = props.dataModel.allStates.dialogflowRestrictedState
  let serviceDirectoryWebhookState = props.dataModel.allStates.serviceDirectoryWebhookState
  const liveMode = false

  return (
  <Box sx={{ width: "75%", mx: "auto"}}>
    <Grid container direction='column' rowSpacing={1}>
      {getControlElem("Webhook Access Authenticated Only?",
        webhookAccessState, 3, 110,
        "/webhook_access_allow_unauthenticated_status", 
        "/update_webhook_access", 
        cloudfunctionsRestrictedState, liveMode)}

      {getControlElem("Webhook Allow Internal Ingress Only?",
        webhookIngressState, 85, 110,
        "/webhook_ingress_internal_only_status", 
        "/update_webhook_ingress", 
        cloudfunctionsRestrictedState, liveMode)}

      {getControlElem("Restrict Cloudfunctions Access to VPC?",
        cloudfunctionsRestrictedState, 15, null,
        "/restricted_services_status_cloudfunctions", 
        "/update_security_perimeter_cloudfunctions", 
        null, liveMode)}

      {getControlElem("Restrict Dialogflow Access to VPC?",
        dialogflowRestrictedState, 15, null,
        "/restricted_services_status_dialogflow", 
        "/update_security_perimeter_dialogflow", 
        null, liveMode)}

      {getControlElem("Route Dialogflow Through VPC Proxy?",
        serviceDirectoryWebhookState, 8, 110,
        "/service_directory_webhook_fulfillment_status", 
        "/update_service_directory_webhook_fulfillment", 
        dialogflowRestrictedState, liveMode)}
    </Grid>
  </Box>
)}

export {StateChangeButtonGrid}