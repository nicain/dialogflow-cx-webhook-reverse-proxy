import React,  {useEffect, useRef} from "react";
import { isError, QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import Switch from '@mui/material/Switch';
import CircularProgress from '@mui/material/CircularProgress';
import {
  Navigate,
} from "react-router-dom";

const TIMER_SCALE = 10;


function getPage(allStates, pageMapper) {
  const curr_array = [null, null, null, null, null]
  for (var stateStr of allStates.stateNames) {
    const idx = pageMapper.order.get(stateStr)
    curr_array[idx] = allStates[stateStr].status
  }
  for (var ii = 0; ii < curr_array.length; ii++) {
    if (curr_array[ii] !== "BLOCKED") {
      pageMapper.stateCache[ii] = curr_array[ii]
    }
  }
  // console.log(curr_array, pageMapper.stateCache, pageMapper.map.get(pageMapper.stateCache))
  return pageMapper.map.get(pageMapper.stateCache)
}

function ToggleStatus(props) {
  const changeRequested = useRef(false);
  const updatePageNumber = useRef(false);

  const {isFetching, refetch} = useQuery(props.endpoint, 
  () =>
  axios
    .post(props.endpoint, {"status": !props.state.status})
    .then((res) => res.data),  {
      enabled:false, 
  })

  useEffect(() => {
    const interval = setInterval(() => {
      props.state.setTimeSinceSliderClick(val => val + 1);
    }, 1000.0/TIMER_SCALE);
    return () => clearInterval(interval);
  }, [props.state]);
  
  useEffect(() => {
    if (updatePageNumber.current) {
      const newPageNumber = getPage(props.state.allStates, props.state.allStates.pageMapper)
      props.state.allStates.setPageNumber(newPageNumber)
      updatePageNumber.current = false
    }
  })

  useEffect(() => {
    if (changeRequested.current) {
      props.state.setStatus(!props.state.status)
      updatePageNumber.current = true
      changeRequested.current = false
      props.state.setTimeSinceSliderClick(0)
    }

    if (isFetching || (props.blocked_by && props.blocked_by.timeSinceSliderClick < props.blocked_by_timeout)) {
      props.state.setIsUpdating(true)
    } else {
      if (props.state.timeSinceSliderClick > props.timeout-1){
        props.state.setIsUpdating(false)
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
        checked={typeof(props.state.status) == "boolean" ? props.state.status : false}
        disabled={typeof(props.state.isUpdating) == "boolean" ? (props.state.isUpdating || props.state.blocked) : false}
        style={{visibility: (props.state.blocked || props.state.isUpdating) ? "hidden" : "visible"}}
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
        <ToggleStatus state={props.state} endpoint={props.endpoint} timeout={props.timeout} blocked_by={props.blocked_by} blocked_by_timeout={props.blocked_by_timeout}/>
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
      enabled: props.state.isUpdating==null ? false : !props.state.isUpdating,
    }
  );

  useEffect(() => {
    if (data && completed.current){
      completed.current = false;
      props.state.setStatus(data.status)
      if (data.status === 'BLOCKED') {
        props.state.setBlocked(true)
      } else {
        props.state.setBlocked(false)
      }
    }
  })

  if (isError && error.response.data === 'NO_TOKEN') {
    return (<Navigate to="/login" />)
  }

  if (props.state.isUpdating) {
    var remainingTimeBlocker = 0
    if (props.blocked_by) {
      remainingTimeBlocker = Math.max(0, props.blocked_by_timeout - 1 - props.blocked_by.timeSinceSliderClick)
    }
    const remainingTime = Math.max(Math.max(0, props.timeout - 1 - props.state.timeSinceSliderClick), remainingTimeBlocker)
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
  } else if (props.state.blocked) {
    return (<div style={{ color: 'red' }}>{"Blocked"}</div>);
  } else {
    return (<div>{(props.state.status) ? "True" : "False"}</div>);
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

export {ExecuteToggleStatus, QueryPollStatus, getPage, TIMER_SCALE}