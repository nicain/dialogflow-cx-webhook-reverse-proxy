import {useEffect, useRef} from "react";
import { QueryClient, QueryClientProvider, useQuery } from "react-query";
import axios from "axios";
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import Login from '@mui/icons-material/Login';
import Logout from '@mui/icons-material/Logout';

function GetPrincipal(props) {

  const {data} = useQuery(props.endpoint, 
  () =>
  axios
    .get(props.endpoint)
    .then((res) => res.data)
  )
  const tooltipTitle = useRef(null);
  const href = useRef(null);
  const loginEnabled = useRef(false);
  const principal = useRef(null);
  useEffect(() => {
    if (data) {
      props.dataModel.projectData.principal.set(data.principal)
      principal.current = data ? data.principal : ""
      const queryStr = new URLSearchParams(props.dataModel.queryParams).toString();

      if (principal.current==="" || principal.current===null || principal.current === undefined) {
        tooltipTitle.current = 'Login'
        href.current = `http://${window.location.host}/session?${queryStr}`
        loginEnabled.current = true
      } else {
        tooltipTitle.current = 'Logout'
        href.current = `http://${window.location.host}/logout?${queryStr}`
        loginEnabled.current = false
      }
    }
  })

  return (
  <div>
    <TextField 
      sx={{mx:2, width: 350, color: 'red'}}
      label={"Principal"} 
      variant="outlined" 
      value={principal.current} 
      placeholder={"Principal"} 
      disabled={true}
      InputLabelProps={{ shrink: principal.current }}
      InputProps={{
        style: { "backgroundColor": loginEnabled.current ? "#ffcdd2" : "transparent" },
        endAdornment: (
          <Tooltip title={tooltipTitle.current} disableInteractive arrow placement="top">
            <InputAdornment position="end">
              <IconButton 
                edge='end' 
                variant="outlined" 
                href={href.current}
                onClick={() => {
                  props.dataModel.loginRedirect.set(true);
                }}
              >
                {loginEnabled.current ? <Login/> : <Logout/>}
              </IconButton>
            </InputAdornment>
          </Tooltip>
        ),
      }}
    />
  </div>
  )
}
  

function QueryPrincipal(props) {
  const queryClient = new QueryClient();
  return (
    <div>
      <QueryClientProvider  client={queryClient}>
        <GetPrincipal 
          endpoint="/get_principal"
          dataModel={props.dataModel}
        />
      </QueryClientProvider>
    </div>
  )
}

export {QueryPrincipal}