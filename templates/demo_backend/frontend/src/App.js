import React from "react";
import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import LoadingSpinner from "./LoadingSpinner";

const queryClient = new QueryClient();

function CloudfunctionsStatus() {
  const { isLoading, error, data} = useQuery("cloudfunctions_status", () =>
    axios
      .get("/cloudfunctions_restricted_status")
      .then((res) => res.data),   {
        refetchInterval: 1000,
      }
  );
  if (isLoading) return "Loading...";
  if (error) return "An error has occurred: " + error.message;

  return (
      <div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
        cloudfunctions.googleapis.com: 
        </div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
          {data.status==null ? "unknown" : data.status.toString()}
        </div>
      </div>
  );
}

function DialogflowStatus() {
  const { isLoading, error, data} = useQuery("dialogflow_status", () =>
    axios
      .get("/dialogflow_restricted_status")
      .then((res) => res.data),   {
        refetchInterval: 1000,
      }
  );
  if (isLoading) return "Loading...";
  if (error) return "An error has occurred: " + error.message;

  return (
      <div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
        dialgflow.googleapis.com: 
        </div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
          {data.status==null ? "unknown" : data.status.toString()}
        </div>
      </div>
  );
}

function ServiceDirectoryWebhookFulfillmentStatus() {
  const {isLoading, error, data} = useQuery("service_directory_webhook_fulfillment_status", () =>
    axios
      .get("/service_directory_webhook_fulfillment_status")
      .then((res) => res.data),   {
        refetchInterval: 1000,
        onSuccess: (data) => {
          const b1 = document.getElementById("SetWebhookFulfillmentGenericBtn");
          const b2 = document.getElementById("SetWebhookFulfillmentServiceDirectoryBtn");
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
        Service Directory Fulfillment: 
        </div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
          {data.status==null ? "unknown" : data.status.toString()}
        </div>
      </div>
  );
}

function SetWebhookFulfillmentServiceDirectory() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_agent_webhook", {"fulfillment": "service-directory"})
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
    <button id="SetWebhookFulfillmentServiceDirectoryBtn" onClick={handleClick}>
      update_agent_webhook_service_directory
    </button>
  )
}

function SetWebhookFulfillmentGeneric() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_agent_webhook", {"fulfillment": "generic-web-service"})
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
    <button id="SetWebhookFulfillmentGenericBtn" onClick={handleClick}>
      update_agent_webhook_generic_webhook
    </button>
  )
}


function WebhookIngressInternalOnlyStatus() {
  const {isLoading, error, data} = useQuery("webhook_ingress_internal_only_status", () =>
    axios
      .get("/webhook_ingress_internal_only_status")
      .then((res) => res.data),   {
        refetchInterval: 1000,
        onSuccess: (data) => {
          const b1 = document.getElementById("WebhookIngressInternalOnlyFalse");
          const b2 = document.getElementById("WebhookIngressInternalOnlyTrue");
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
        webhook_ingress_internal_only: 
        </div>
        <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
          {data.status==null ? "unknown" : data.status.toString()}
        </div>
      </div>
  );
}


function WebhookIngressInternalOnlyTrue() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_webhook_ingress", {"internal_only": true})
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
    <button id="WebhookIngressInternalOnlyTrue" onClick={handleClick}>
      update_webhook_ingress_vpc_only
    </button>
  )
}

function WebhookIngressInternalOnlyFalse() {
  const { isFetching, isError, refetch } = useQuery('key', 
  () =>
  axios
    .post("/update_webhook_ingress", {"internal_only": false})
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
    <button id="WebhookIngressInternalOnlyFalse" onClick={handleClick}>
      update_webhook_ingress_public
    </button>
  )
}

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
}


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
}

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
}



export default function App() {
  return (
    <div>
      <QueryClientProvider client={queryClient}>
        <CloudfunctionsStatus /><br />
        <DialogflowStatus /><br />
        <ServiceDirectoryWebhookFulfillmentStatus />
        <SetWebhookFulfillmentServiceDirectory />
        <SetWebhookFulfillmentGeneric /><br />
        <WebhookIngressInternalOnlyStatus />
        <WebhookIngressInternalOnlyTrue />
        <WebhookIngressInternalOnlyFalse /><br />
        <WebhookAccessAllowUnauthenticated />
        <WebhookAccessAllowUnauthenticatedTrue />
        <WebhookAccessAllowUnauthenticatedFalse />
      </QueryClientProvider>
    </div>
  );
}



// // export default App;

// // import logo from './logo.svg';
// import './App.css';
// import React, { useState, useEffect, useRef } from 'react';
// import LoadingSpinner from "./LoadingSpinner";
// import "./styles.css";


// export const useInterval = (callback, delay) => {
//   const savedCallback = useRef();
//   useEffect(() => {
//     savedCallback.current = callback;
//   }, [callback]);


//   useEffect(() => {
//     function tick() {
//       savedCallback.current();
//     }
//     if (delay !== null) {
//       const id = setInterval(tick, delay);
//       return () => clearInterval(id);
//     }
//   }, [delay]);
// }

// export default function App() {
//   const [service, setService] = useState([]);
//   const [isLoading, setIsLoading] = useState(false);
//   const [errorMessage, setErrorMessage] = useState("");
//   const handleFetch = () => {
//     setIsLoading(true);
//     fetch("/get_status?restricted_services=true")
//       .then((respose) => respose.json())
//       .then((respose) => {
//         setService(respose)
//         setIsLoading(false)
//       })
//       .catch(() => {
//          setErrorMessage("Unable to fetch");
//          setIsLoading(false);
//       });
//   };
//   const renderService = (
//     <div>
//       <div style={{ float: "left", paddingRight: "5px" }}>
//         cloudfunctions_restricted:
//       </div>
//       <div style={{ float: "left", paddingRight: "5px" }}>
//         {service.cloudfunctions_restricted==null ? "unknown" : service.cloudfunctions_restricted.toString()}
//       </div>
//       <button onClick={handleFetch} disabled={isLoading} style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
//         Fetch Service Status
//       </button>
//     </div>
//   );

//   function Counter() {
//     const delay=1000;
//     const [count, setCount] = useState(0);
  
//     // Increment the counter.
//     useInterval(() => {
//       setCount(count + 1);
//     }, delay);

//     // const foo = fetch("/get_status?restricted_services=true")
//     // .then((respose) => respose.json())
  
//     return (
//       <>
//         <h1>Counter: {count}</h1>
//         {/* <h1>foo: {foo}</h1> */}
//       </>
//     );
//   }

//   return (
//     <div className="App">
//       {isLoading ? <LoadingSpinner /> : renderService}
//       {errorMessage && <div className="error">{errorMessage}</div>}
//       {Counter()}
//     </div>
//   );
// }






// // function App() {
// //   return (
// //     <div className="App">
// //       <header className="App-header">
// //         <img src={logo} className="App-logo" alt="logo" />
// //         <p>
// //           Edit <code>src/App.js</code> and save to reload.
// //         </p>
// //         <a
// //           className="App-link"
// //           href="https://reactjs.org"
// //           target="_blank"
// //           rel="noopener noreferrer"
// //         >
// //           Learn React
// //         </a>
// //       </header>
// //     </div>
// //   );
// // }

// // export default App;



// function Example() {
//   const { isLoading, error, data, refetch} = useQuery("example", () =>
//     axios
//       .get("/get_status?restricted_services=true")
//       .then((res) => res.data),   {
//         refetchInterval: 1000,
//       }
//   );
//   if (isLoading) return "Loading...";
//   if (error) return "An error has occurred: " + error.message;

//   const handleClick = () => {
//     // manually refetch
//     refetch();
//   };

//   return (
//       <div>
//         <div style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
//           {data.cloudfunctions_restricted==null ? "unknown" : data.cloudfunctions_restricted.toString()}
//         </div>
//         <button onClick={handleClick} style={{ float: "left", paddingRight: "5px", justifyContent: 'center',}}>
//           Fetch Service Status
//         </button>
//       </div>
//   );
// }