import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import CircularProgress from '@mui/material/CircularProgress';
import {useEffect} from 'react';

function CloudfunctionsStatus() {
  const { isLoading, error, data} = useQuery("cloudfunctions_status", () =>
    axios
      .get("/restricted_services_status", {
        withCredentials: true,
      })
      .then((res) => res.data),   {
        refetchInterval: 5000,
        retry:false,
      }
  );
  if (isLoading) return <CircularProgress />;
  if (error) return "An error has occurred: " + error.message;

  return (
      <div>
        {data.cloudfunctions_restricted==null ? "unknown" : data.cloudfunctions_restricted.toString()}
      </div>
  );
}

function QueryCloudfunctionsStatus() {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <CloudfunctionsStatus />
      </QueryClientProvider>
    </div>
  )
}

function DialogflowStatus(props) {
  const { isLoading, error, data} = useQuery("cloudfunctions_status", () =>
    axios
      .get("/restricted_services_status", {withCredentials: true})
      .then((res) => res.data),   {
        refetchInterval: 5000,
        retry:false,
      }
  );

  useEffect(() => {
    if (data != null) {
      props.state.setStatus(data.dialogflow_restricted)
    }}
  )


  //     if (data.dialogflow_restricted === false) {
  //       console.log('trying to change state to false:')
  //       props.state.setStatus(true)
  //     }
  //     console.log('here', data.dialogflow_restricted)
  //     // props.state.setIsUpdating(false)
  //   } else {
  //     // props.state.setStatus(null)
  //     // props.state.setIsUpdating(true)
  //   }
  // });

  if (isLoading || props.state.isUpdating) {
    return <CircularProgress />;
  }
    
  if (error) return "An error has occurred: " + error.message;

  return (
      <div>
        {data.dialogflow_restricted==null ? "unknown" : data.dialogflow_restricted.toString()}
      </div>
  );
}

function QueryDialogflowStatus(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <DialogflowStatus state={props.state}/>
      </QueryClientProvider>
    </div>
  )
}

function ServiceDirectoryWebhookFulfillmentStatus() {
  const {isLoading, error, data} = useQuery("service_directory_webhook_fulfillment_status", () =>
    axios
      .get("/service_directory_webhook_fulfillment_status", {withCredentials: true})
      .then((res) => res.data),   {
        refetchInterval: 5000,
      }
  );
  if (isLoading) return <CircularProgress />;
  if (error) return "An error has occurred: " + error.message;
  return (
      <div>
        {data.service_directory_webhook_fulfillment==null ? "unknown" : data.service_directory_webhook_fulfillment.toString()}
      </div>
  );
}

function QueryServiceDirectoryWebhookFulfillmentStatus() {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <ServiceDirectoryWebhookFulfillmentStatus />
      </QueryClientProvider>
    </div>
  )
}

function WebhookIngressInternalOnlyStatus() {
  const {isLoading, error, data} = useQuery("webhook_ingress_internal_only_status", () =>
    axios
      .get("/webhook_ingress_internal_only_status", {withCredentials: true})
      .then((res) => res.data),   {
        refetchInterval: 1000,
      }
  );
  if (isLoading) return <CircularProgress />;
  if (error) return "An error has occurred: " + error.message;
  return (
      <div>
        {data.webhook_ingress_internal_only_status==null ? "unknown" : data.webhook_ingress_internal_only_status.toString()}
      </div>
  );
}

function QueryWebhookIngressInternalOnlyStatus() {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <WebhookIngressInternalOnlyStatus />
      </QueryClientProvider>
    </div>
  )
}


export {QueryCloudfunctionsStatus, QueryDialogflowStatus, QueryServiceDirectoryWebhookFulfillmentStatus, QueryWebhookIngressInternalOnlyStatus}
