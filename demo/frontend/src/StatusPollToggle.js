import React,  {useEffect, useRef} from "react";
import { isError, QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import Switch from '@mui/material/Switch';
import CircularProgress from '@mui/material/CircularProgress';
import {
  Navigate,
} from "react-router-dom";
import {getPage} from './DataModel.js';

const TIMER_SCALE = 10;

function ToggleStatus(props) {

  const changeRequested = useRef(false);
  const updatePageNumber = useRef(false);

  const {isFetching, refetch} = useQuery(props.endpoint, 
  () =>
  axios
    .post(props.endpoint, {"status": !props.state.status.current})
    .then((res) => res.data),  {
      enabled:false, 
  })

  useEffect(() => {
    const interval = setInterval(() => {
      props.state.timeSinceSliderClick.set(val => val + 1);
    }, 1000.0/TIMER_SCALE);
    return () => clearInterval(interval);
  }, [props.state]);
  
  useEffect(() => {
    if (updatePageNumber.current) {
      const newPageNumber = getPage(props.allStates, props.pageMapper)
      props.pageNumber.set(newPageNumber)
      updatePageNumber.current = false
    }
  })

  useEffect(() => {
    if (changeRequested.current) {
      props.state.status.set(!props.state.status.current)
      updatePageNumber.current = true
      changeRequested.current = false
      props.state.timeSinceSliderClick.set(0)
    }

    if (isFetching || (props.blocked_by && props.blocked_by.timeSinceSliderClick.current < props.blocked_by_timeout)) {
      props.state.isUpdating.set(true)
    } else {
      if (props.state.timeSinceSliderClick.current > props.timeout-1){
        props.state.isUpdating.set(false)
      }
    }
  });
  
  function onChange() {
    changeRequested.current = true
    refetch()
  }

  return (
    <>
      {<Switch
        onChange={onChange} 
        checked={typeof(props.state.status.current) == "boolean" ? props.state.status.current : false}
        disabled={typeof(props.state.isUpdating.current) == "boolean" ? (props.state.isUpdating.current || props.state.blocked.current) : false}
        style={{visibility: (props.state.blocked.current || props.state.isUpdating.current) ? "hidden" : "visible"}}
        color="secondary"
      />}
    </>
  )
}

function ExecuteToggleStatus(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <ToggleStatus 
          state={props.state} 
          endpoint={props.endpoint} 
          timeout={props.timeout} 
          blocked_by={props.blocked_by} 
          blocked_by_timeout={props.blocked_by_timeout}
          allStates={props.allStates}
          pageMapper={props.pageMapper}
          pageNumber={props.pageNumber}
        />
      </QueryClientProvider>
    </div>
  )
}

function PollStatus(props) {
  const completed = useRef(false);

  function onSuccess() {
    completed.current = true;
  }
  function queryFunction () {
    return axios
    .get(props.endpoint)
    .then((res) => res.data)
  }

  const {data, isError, error} = useQuery(
    props.endpoint, queryFunction,
    {
      refetchInterval: 10000,
      onSuccess: onSuccess,
      retry: false,
      enabled: props.state.isUpdating.current==null ? false : !props.state.isUpdating.current,
    }
  );

  useEffect(() => {
    if (data && completed.current){
      completed.current = false;
      props.state.status.set(data.status)
      if (data.status === 'BLOCKED') {
        props.state.blocked.set(true)
      } else {
        props.state.blocked.set(false)
      }
    }
  })

  if (isError && error.response.data === 'NO_TOKEN') {
    return (<Navigate to="/login" />)
  }

  if (props.state.isUpdating.current) {
    var remainingTimeBlocker = 0
    if (props.blocked_by) {
      remainingTimeBlocker = Math.max(0, props.blocked_by_timeout - 1 - props.blocked_by.timeSinceSliderClick.current)
    }
    const remainingTime = Math.max(Math.max(0, props.timeout - 1 - props.state.timeSinceSliderClick.current), remainingTimeBlocker)
    if (remainingTime > 0) {
      // console.log(props.blocked_by_timeout, props.timeout)
      var startTime
      if (remainingTimeBlocker > 0) {
        startTime = Math.max(props.blocked_by_timeout - 1, props.timeout - 1)
      } else {
        startTime = props.timeout - 1
      }
      // console.log('remainingTime', remainingTime, startTime, remainingTime/startTime, 100.0*(remainingTime/startTime))
      return <CircularProgress size={20} variant={"determinate"} value={100.0*(remainingTime/startTime)}/>;
    }
    return <CircularProgress size={20}/>;
  } else if (props.state.blocked.current) {
    return (<div style={{ color: 'red' }}>{"Blocked"}</div>);
  } else {
    return (<div>{(props.state.status.current) ? "True" : "False"}</div>);
  }
}

function QueryPollStatus(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <PollStatus state={props.state} endpoint={props.endpoint} timeout={props.timeout} blocked_by={props.blocked_by} blocked_by_timeout={props.blocked_by_timeout}/>
      </QueryClientProvider>
    </div>
  )
}

export {ExecuteToggleStatus, QueryPollStatus, TIMER_SCALE}