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

  // console.log(props.dataModel.projectData, props.dataModel.projectData.project_id.current.project_id)

  // console.log(props.dataModel.projectData.project_id, data)
  useEffect(() => {
    if (data) {
      props.dataModel.projectData.project_id.set(data.project_id)
    }
    // props.setProjectInfo(data)
  }) 
}

function QueryInfo(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <Info endpoint="/info" dataModel={props.dataModel}/>
      </QueryClientProvider>
    </div>
  )
}

export {QueryInfo}