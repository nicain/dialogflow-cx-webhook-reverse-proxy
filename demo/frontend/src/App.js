import React,  {useState, useEffect, useRef} from "react";
import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";
import {QueryCloudfunctionsStatus, QueryDialogflowStatus, QueryServiceDirectoryWebhookFulfillmentStatus, QueryWebhookIngressInternalOnlyStatus} from "./Status.js"
import Button from '@mui/material/Button';
import 'typeface-roboto'
import Stack from '@mui/material/Stack';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { styled } from "@mui/material/styles";
import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import CircularProgress from '@mui/material/CircularProgress';
import CachedIcon from '@mui/icons-material/Cached';
import Switch from '@mui/material/Switch';
import {ExecuteToggleStatus, QueryPollStatus, getPage, TIMER_SCALE} from "./StatusPollToggle.js"
import {StatusTutorialMode, ToggleStatusTutorialMode} from "./TutorialMode.js"
import { Document, Page } from 'react-pdf';
import diagram_sd from './VPC_SC_diagram_latest.pdf';
import {QueryInfo} from './Info.js'



function DebugPrintData(props) {
  const content = JSON.stringify(props.data, null, 2)
  function onClick() {
    return navigator.clipboard.writeText(content)
  }
  return(
  <div>
    <pre>
      <Button sx={{ textAlign: 'left' }} onClick={onClick} variant="contained" color="primary" >{content}</Button> 
    </pre>
  </div>
  
)}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
       </Routes>
    </BrowserRouter>
  );
}


const Item = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  padding: 0,
  textAlign: "right",
  color: theme.palette.text.secondary,
}));

// function get

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
  return (
  <Box sx={{ width: "75%", mx: "auto"}}>
    <Grid container direction='column' rowSpacing={1}>
      {getControlElem("Webhook Access Authenticated Only?",
        props.webhookAccessState, 3, 110,
        "/webhook_access_allow_unauthenticated_status", 
        "/update_webhook_access", 
        props.cloudfunctionsRestrictedState, props.liveMode)}

      {getControlElem("Webhook Allow Internal Ingress Only?",
        props.webhookIngressState, 85, 110,
        "/webhook_ingress_internal_only_status", 
        "/update_webhook_ingress", 
        props.cloudfunctionsRestrictedState, props.liveMode)}

      {getControlElem("Restrict Cloudfunctions Access to VPC?",
        props.cloudfunctionsRestrictedState, 15, null,
        "/restricted_services_status_cloudfunctions", 
        "/update_security_perimeter_cloudfunctions", 
        null, props.liveMode)}

      {getControlElem("Restrict Dialogflow Access to VPC?",
        props.dialogflowRestrictedState, 15, null,
        "/restricted_services_status_dialogflow", 
        "/update_security_perimeter_dialogflow", 
        null, props.liveMode)}

      {getControlElem("Route Dialogflow Through VPC Proxy?",
        props.serviceDirectoryWebhookState, 8, 110,
        "/service_directory_webhook_fulfillment_status", 
        "/update_service_directory_webhook_fulfillment", 
        props.dialogflowRestrictedState, props.liveMode)}
    </Grid>
  </Box>
)}


function NewInitState(name, allStates) {
  var stateContainer = {
    name: name,
    isUpdating: null,
    setIsUpdating: null,
    status: null,
    setStatus: null,
    blocked: null,
    setBlocked: null,
    timeSinceSliderClick: null,
    setTimeSinceSliderClick: null,
    allStates: allStates
  };
  [stateContainer.isUpdating, stateContainer.setIsUpdating] = useState(true);
  [stateContainer.status, stateContainer.setStatus] = useState(false);
  [stateContainer.blocked, stateContainer.setBlocked] = useState(false);
  [stateContainer.timeSinceSliderClick, stateContainer.setTimeSinceSliderClick] = useState(1000*TIMER_SCALE);
  allStates[name] = {
    'status':stateContainer.status,
    'setStatus':stateContainer.setStatus,
    'setIsUpdating':stateContainer.setIsUpdating,
    'setBlocked':stateContainer.setBlocked,
    'setTimeSinceSliderClick':stateContainer.setTimeSinceSliderClick,
    'timeSinceSliderClick':stateContainer.timeSinceSliderClick,
  }
  allStates.stateNames.push(name)
  return stateContainer
}

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

const pageMapper = BuildMapPageNumberToState()

function allStatesToPageInfo(allStates) {

  const state = {}
  const curr_array = [null, null, null, null, null]
  for (var stateStr of allStates.stateNames) {
    const idx = pageMapper.order.get(stateStr)
    curr_array[idx] = allStates[stateStr].status
    state[stateStr] = allStates[stateStr].status
  }
  
  return {page: getPage(allStates, pageMapper), state:state}
}

function StateImages(props) {
  const pageHeight = 300
  return(
  <Box sx={{ width: "75%"}} display="flex" justifyContent="center" alignItems="center" margin="auto">
    <Document file={diagram_sd}>
      <Page pageNumber={props.curr_page} height={pageHeight} loading={<div><Box sx={{ width: "75%"}} display="flex" justifyContent="center" alignItems="center" margin="auto"><Paper variant="string" sx={{ width: "75%", height:pageHeight}}></Paper></Box></div>}/>
    </Document>
  </Box>
)}

function InfoBanner(props) {
  const content = JSON.stringify(props.projectInfo, null, 2)
  function onClick() {
    return navigator.clipboard.writeText(content)
  }
  if (props.liveMode) {
    return (
      <Box sx={{ width: "50%"}} display="flex" justifyContent="center" alignItems="center" margin="auto">
        <pre>
          <Button sx={{ textAlign: 'left' }} onClick={onClick} variant="contained" color="primary" >{content}</Button> 
        </pre>
      </Box>
    )
    } else {
    return <></>
  }
}

function Home() {
  const [liveMode, setLiveMode] = useState(false);
  const [projectInfo, setProjectInfo] = useState({});
  const [pageNumber, setPageNumber] = useState(33);
  const allStates = {
    dialogflowRestrictedState: null,
    cloudfunctionsRestrictedState: null,
    webhookAccessState: null,
    webhookIngressState: null,
    serviceDirectoryWebhookState: null,
    pageNumber: pageNumber,
    setPageNumber: setPageNumber,
    pageMapper: pageMapper,
    stateNames: [],
  }
  var dialogflowRestrictedState = NewInitState("dialogflowRestrictedState", allStates)
  var webhookIngressState = NewInitState("webhookIngressState", allStates)
  var cloudfunctionsRestrictedState = NewInitState("cloudfunctionsRestrictedState", allStates)
  var webhookAccessState = NewInitState("webhookAccessState", allStates)
  var serviceDirectoryWebhookState = NewInitState("serviceDirectoryWebhookState", allStates)
  const curr_page = getPage(allStates, pageMapper) ? getPage(allStates, pageMapper) : 33
  return (
    <div>
      <h2>Home</h2>
      {<LogoutButton />}
      {<LiveMode liveMode={liveMode} setLiveMode={setLiveMode} allStates={allStates} projectInfo={projectInfo}/>}
      {<InfoBanner projectInfo={projectInfo} liveMode={liveMode}/>}
      {/* {<DebugPrintData data={allStatesToPageInfo(allStates)}/>} */}
      {<StateImages curr_page={curr_page}/>}
      {<StateChangeButtonGrid 
        dialogflowRestrictedState={dialogflowRestrictedState}
        cloudfunctionsRestrictedState={cloudfunctionsRestrictedState}
        webhookAccessState={webhookAccessState}
        webhookIngressState={webhookIngressState}
        serviceDirectoryWebhookState={serviceDirectoryWebhookState}
        liveMode={liveMode}
      />}
      {<QueryInfo setProjectInfo={setProjectInfo}/>}
    </div>
  );
}

function Login() {
  return (
    <div>
      <h2>Home</h2>
      {<LoginButton />}
      {<StateImages curr_page={33}/>}
    </div>
  );
      }

function LiveMode(props) {

  const timeSinceLiveModeEnabled = useRef(0);

  useEffect(() => {
    const interval = setInterval(() => {
      timeSinceLiveModeEnabled.current += 1;
    }, 1000.0/TIMER_SCALE);
    return () => clearInterval(interval);
  }, [props.state]);

  function onChange() {
    const previousLiveModeState = props.liveMode
    props.setLiveMode(!props.liveMode)
    if (previousLiveModeState === true) {
      for (var stateStr of props.allStates.stateNames) {
        props.allStates[stateStr].setStatus(false)
        props.allStates[stateStr].setIsUpdating(false)
        props.allStates[stateStr].setBlocked(false)
      }
    } else if (previousLiveModeState === false) {
      timeSinceLiveModeEnabled.current = 0
      console.log(props.projectInfo)
    }
  }
  return (
    <div>
      <Paper variant='string'>Live Demo</Paper>
      {<Switch 
        onChange={onChange} 
        checked={typeof(props.liveMode) == "boolean" ? props.liveMode : true}
        color="secondary"
      />}
    </div>
  )
}


function LogoutButton() {
  return (
    <form>
      <Button href={`http://${window.location.host}/logout`} variant="contained">Logout</Button>
    </form>
  )
}

function LoginButton() {
  return (
    <form>
      <Button href={`http://${window.location.host}/session`} variant="contained">Login</Button>
    </form>
  )
}


// const PingItem = styled(Paper)(({ theme }) => ({
//   ...theme.typography.body2,
//   padding: theme.spacing(1),
//   color: theme.palette.text.secondary
// }));


// function PingWebhook(props) {
//   const { isFetching, isError, refetch, data} = useQuery(props.key, 
//   () =>
//   axios
//     .get(props.endpoint, {"params":{"authenticated": props.authenticated}})
//     .then((res) => res.data),  
//     {
//       enabled:false, 
//       retry:false,
//     }
//   )
//   props.pingStatus.anyFetching = (props.pingStatus.anyFetching || isFetching)
//   props.pingStatus.anyError = (props.pingStatus.anyError || isError)
//   props.pingStatus[props.key] = (data == null) ? null : data.status
//   return refetch
// }


// function PingQuery() {
//   var pingStatus = {
//     anyFetching: false,  
//     anyError: false,  
//     ping_webhook_internal_auth: null,
//     ping_webhook_internal_noauth: null,
//     ping_webhook_external_auth: null,
//     ping_webhook_external_noauth: null,
//   }
  
//   const refetch_internal_auth = PingWebhook({"pingStatus":pingStatus, 'authenticated':true, 'key':"ping_webhook_internal_auth", 'endpoint':"/ping_webhook"})
//   const refetch_internal_noauth = PingWebhook({"pingStatus":pingStatus, 'authenticated':false, 'key':"ping_webhook_internal_noauth", 'endpoint':"/ping_webhook"})
//   const refetch_external_auth = PingWebhook({"pingStatus":pingStatus, 'authenticated':true, 'key':"ping_webhook_external_auth", 'endpoint':"/ping_webhook_external_proxy"})
//   const refetch_external_noauth = PingWebhook({"pingStatus":pingStatus, 'authenticated':false, 'key':"ping_webhook_external_noauth", 'endpoint':"/ping_webhook_external_proxy"})
  
//   if (pingStatus.anyFetching) {
//     return <CircularProgress />
//     }
//   else if (pingStatus.anyError) {
//     return "error encountered"
//   }

//   var refetch = () => {
//     refetch_internal_auth(); 
//     refetch_internal_noauth();
//     refetch_external_auth(); 
//     refetch_external_noauth();
//   }  
//   return (
//     <div>
//       <Button onClick={refetch} variant="contained" color="secondary" startIcon={<CachedIcon />}>Ping!</Button>
//     </div>
// )}



// function PingWebhookExternal() {
//   const { isFetching, isError, refetch, data} = useQuery("ping_webhook_external", 
//     () =>
//     axios
//       .get('/ping_webhook_external_proxy')
//       .then((res) => res.data),  {
//         enabled:false, 
//     })
  
//   if (isFetching) {
//     return <CircularProgress />
//     }
//   else if (isError) {
//     return "error encountered"
//   }

//   console.log(data)

//   return (
//     <div>
//       <Button onClick={refetch} variant="contained" color="secondary" >Ping!</Button>
//     </div>
// )}


// function PingButton() {
//   const queryClient = new QueryClient();
//   return (
//     <div>
//       <QueryClientProvider  client={queryClient}>
//         <PingQuery />
//       </QueryClientProvider>
//     </div>
// )}

// function PingGrid(args) {
//   return (
//   <Box sx={{ width: "75%", mx: "auto"}}>
//     <Grid container direction={'row'} columnSpacing={1}>
//       <Grid item xs={3}>
//         <></>
//         <PingItem sx={{my: 1}} variant="string">{<PingButton />}</PingItem>
//         <PingItem sx={{my: 1}} variant="string">External-to-webhook</PingItem>
//         <PingItem sx={{my: 1}} variant="string">Internal-to-webhook</PingItem>
//         <PingItem sx={{my: 1}} variant="string">External-to-dialogflow</PingItem>
//         <PingItem sx={{my: 1}} variant="string">Internal-to-dialogflow</PingItem>
//       </Grid>
//       <Grid item xs={2}>
//         <Item variant="string">Authenticated</Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//       </Grid>
//       <Grid item xs={2}>
//         <Item variant="string">Unauthenticated</Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//         <Item sx={{my: 1}}><div>null</div></Item>
//         <Item sx={{my: 1}} variant="string"><div></div></Item>
//         <Item sx={{my: 1}} variant="string"><div></div></Item>
//       </Grid>
//     </Grid>
//   </Box>
// )}





// function ExecuteWebhookAccessAllowUnauthenticated(props) {
//   const queryClient = new QueryClient();
//   return (
//     <div>
//       <QueryClientProvider  client={queryClient}>
//         <WebhookAccessAllowUnauthenticated state={props.state}/>
//       </QueryClientProvider>
//     </div>
//   )
// }

// const SystemItem = styled(Paper)(({ theme }) => ({
//   ...theme.typography.body2,
//   padding: theme.spacing(1),
//   color: theme.palette.text.secondary
// }));


// function StatusGrid(props) {
//   return (
//   <Box sx={{ width: "75%", mx: "auto"}}>
//     <Grid container direction={'row'} columnSpacing={3}>
//       <Grid item xs={6}>
//         <Item variant="string">System:</Item>
//         {/* <SystemItem variant="string" sx={{my: 1}}>cloudfunctions.googleapis.com restricted?</SystemItem> */}
//         {/* <SystemItem variant="string" sx={{my: 1}}>dialogflow.googleapis.com restricted?</SystemItem> */}
//         {/* <SystemItem variant="string" sx={{my: 1}}>Service Directory Webhook Fulfillment?</SystemItem> */}
//         {/* <SystemItem variant="string" sx={{my: 1}}>Webhook Access Internal Only?</SystemItem> */}
//         {/* <SystemItem variant="string" sx={{my: 1}}>Webhook Access Allow Unauthenticated?</SystemItem> */}
//       </Grid>
//       <Grid item xs={6}>
//         <Item variant="string">Status:</Item>
//         {/* <Item sx={{my: 1}}>{<QueryCloudfunctionsStatus />}</Item> */}
//         {/* <Item sx={{my: 1}}>{<QueryDialogflowStatus state={props.dialogFlowState}/>}</Item> */}
//         {/* <Item sx={{my: 1}}>{<QueryServiceDirectoryWebhookFulfillmentStatus />}</Item>
//         <Item sx={{my: 1}}>{<QueryWebhookIngressInternalOnlyStatus />}</Item>  */}
//         {/* <Item sx={{my: 1}}>{<QueryWebhookAccessStatus state={props.webhookAccessState}/>}</Item> */}
//       </Grid>
//     </Grid>
//   </Box>
// )}


    {/* <Grid container direction={'row'} columnSpacing={3}>
      <Item variant="string">Set Webhook Access to Allow Unauthenticated:</Item> */}
      {/* {<ExecuteWebhookAccessAllowUnauthenticated 
        state={props.webhookAccessAllowUnauthenticatedState}
        />}
      {<ExecuteWebhookAccessAllowUnauthenticated
        setBlocking={props.webhookAccessAllowUnauthenticatedState.setFalseUpdating}
        setValue={false}
        queryKey={"bar"}
        status={props.webhookAccessAllowUnauthenticatedState.status}
      />} */}
    {/* </Grid> */}

      {/* {<StatusGrid 
        dialogFlowState={dialogFlowState}
        webhookAccessState={webhookAccessState}
      />} */}