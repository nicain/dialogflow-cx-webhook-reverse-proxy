import {useEffect} from "react";
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
  useEffect(() => {
    if (data) {
      props.dataModel.projectData.principal.set(data.principal)
    }
  })

  const principal = data ? data.principal : ""

  var tooltipTitle
  var button
  var href
  if (principal === "" || principal===null) {
    tooltipTitle = 'Login'
    button = <Login/>
    href = `http://${window.location.host}/session`
  } else {
    tooltipTitle = 'Logout'
    button = <Logout/>
    href = `http://${window.location.host}/logout`
  }

  return (
  <div>
    <TextField 
      sx={props.sx ? props.sx: {mx:2, width: 350}} 
      label={"Principal"} 
      variant="outlined" 
      value={principal} 
      placeholder={"Principal"} 
      disabled={true}

      InputProps={{
        endAdornment: (
          <Tooltip title={tooltipTitle} disableInteractive arrow placement="right">
            <InputAdornment position="end">
              <IconButton edge='end' variant="outlined" href={href}>
                 {button}
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