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


// function Foo() {

//   const [anchorEl, setAnchorEl] = useState(null);
//   const handleClick = (event) => {
//     setAnchorEl(event.currentTarget);
//   };

//   const handleClose = () => {
//     setAnchorEl(null);
//   };

//   const open = Boolean(anchorEl);
//   const id = open ? 'simple-popover' : undefined;

//   return (
//     <div>
//       <Button aria-describedby={id} variant="contained" onClick={handleClick} startIcon={<Terminal />} sx={{ p: 1 }}>
//         Try it!
//       </Button>
//       <Popover
//         id={id}
//         open={open}
//         anchorEl={anchorEl}
//         onClose={handleClose}
//         anchorOrigin={{
//           vertical: 'center',
//           horizontal: 'right',
//         }}
//       >
//         <Typography sx={{ p: 2 }}>The content of the Popover.</Typography>
//       </Popover>
//     </div>
//   );

// }


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
  <Grid container item direction='row' columnSpacing={3} justifyContent="flex-start" alignItems="center">
    <Box sx={{ width: 270 }}>
      <Item sx={{my: 0}} variant="string">{title}</Item>
    </Box>
    <Box sx={{ width: 60 }}>
      <Item sx={{my: 0}} variant="string">{statusElem}</Item>
    </Box>
    <Item sx={{my: 0}} variant="string">{toggleStatusElem}</Item>

    {/* <Foo /> */}
  </Grid>
)}

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
  <Box sx={{ width: "75%", mx: "auto"}}>
    <Grid container direction='column' rowSpacing={1}>
      {getControlElem("Webhook Access Authenticated Only?",
        webhookAccessState, 3, 110,
        "/webhook_access_allow_unauthenticated_status", 
        "/update_webhook_access", 
        cloudfunctionsRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}

      {getControlElem("Webhook Allow Internal Ingress Only?",
        webhookIngressState, 85, 110,
        "/webhook_ingress_internal_only_status", 
        "/update_webhook_ingress", 
        cloudfunctionsRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}

      {getControlElem("Restrict Cloudfunctions Access to VPC?",
        cloudfunctionsRestrictedState, 15, null,
        "/restricted_services_status_cloudfunctions", 
        "/update_security_perimeter_cloudfunctions", 
        null, liveMode, dataModel, pageMapper, pageNumber)}

      {getControlElem("Restrict Dialogflow Access to VPC?",
        dialogflowRestrictedState, 15, null,
        "/restricted_services_status_dialogflow", 
        "/update_security_perimeter_dialogflow", 
        null, liveMode, dataModel, pageMapper, pageNumber)}

      {getControlElem("Route Dialogflow Through VPC Proxy?",
        serviceDirectoryWebhookState, 8, 110,
        "/service_directory_webhook_fulfillment_status", 
        "/update_service_directory_webhook_fulfillment", 
        dialogflowRestrictedState, liveMode, dataModel, pageMapper, pageNumber)}
    </Grid>
  </Box>
)}

export {StateChangeButtonGrid}