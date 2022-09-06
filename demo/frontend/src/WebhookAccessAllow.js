import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import LoadingSpinner from "./LoadingSpinner";

const queryClient2 = new QueryClient();


function WebhookAccessAllowUnauthenticated() {
  const {isLoading, error, data} = useQuery("update_webhook_access", () =>
    axios
      .get("/webhook_access_allow_unauthenticated")
      .then((res) => res.data),   {
        refetchInterval: 1000,
        onSuccess: (data) => {
          const b1 = document.getElementById("WebhookAccessAllowUnauthenticatedFalse");
          const b2 = document.getElementById("WebhookAccessAllowUnauthenticatedTrue");
          if (data.status != null && b1 != null && b2 != null) {
            if (data.status === true) {
              b1.disabled = false;
              b2.disabled = true;
            } else {
              b1.disabled = true;
              b2.disabled = false;
            };
          };
        }
      }
  );
  if (isLoading) return "Loading...";
  if (error) return "An error has occurred: " + error.message;
  return (
      <div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
        webhook_access_allow_unauthenticated: 
        </div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
          {data.status==null ? "unknown" : data.status.toString()}
        </div>
      </div>
  );
};


function WebhookAccessAllowUnauthenticatedTrue() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_webhook_access", {"allow_unauthenticated": true})
    .then((res) => res.data),
  {enabled:false})
  if (isFetching) {
      return <LoadingSpinner />
  }
  else if (isError) {
      return "error encountered"
  }
  const handleClick = () => {
    refetch();
  };
  return (
    <button id="WebhookAccessAllowUnauthenticatedTrue" onClick={handleClick}>
      update_webhook_public
    </button>
  )
};

function WebhookAccessAllowUnauthenticatedFalse() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_webhook_access", {"allow_unauthenticated": false})
    .then((res) => res.data),
  {enabled:false})
  if (isFetching) {
      return <LoadingSpinner />
  }
  else if (isError) {
      return "error encountered"
  }
  const handleClick = () => {
    refetch();
  };
  return (
    <button id="WebhookAccessAllowUnauthenticatedFalse" onClick={handleClick}>
      update_webhook_private
    </button>
  )
};

function WebhookAccess() {
  return (
  <div>
    {/* <QueryClientProvider  client={queryClient2}>
      <WebhookAccessAllowUnauthenticated />
      <WebhookAccessAllowUnauthenticatedTrue />
      <WebhookAccessAllowUnauthenticatedFalse />
    </QueryClientProvider> */}
  </div>
  )

  // return (
  //     <WebhookAccessAllowUnauthenticated /> 
  // )
  // "foo"
};

export {WebhookAccess, WebhookAccessAllowUnauthenticated}