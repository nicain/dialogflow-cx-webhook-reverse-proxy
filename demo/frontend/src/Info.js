import React,  {useEffect} from "react";
import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";

function Info(props) {

  function queryFunction () {
    return axios
    .get(props.endpoint)
    .then((res) => res.data)
  }

  const {data, } = useQuery(
    props.endpoint, queryFunction,
    {
      refetchInterval: 30000,
      retry: false,
    }
  );

  useEffect(() => {
    props.setProjectInfo(data)
  })

}

function QueryInfo(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <Info endpoint="/info" setProjectInfo={props.setProjectInfo}/>
      </QueryClientProvider>
    </div>
  )
}

export {QueryInfo}