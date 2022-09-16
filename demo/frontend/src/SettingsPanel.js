import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import Replay from '@mui/icons-material/Replay';
import Tooltip from '@mui/material/Tooltip';
import Link from '@mui/material/Link';
import { QueryPrincipal } from './QueryPrincipal';

import {webhook_name_default} from './DataModel'

function TextInputField(props) {
  
  function onChange (e) {
    props.setting.set(e.target.value)
  }

  return (
    <TextField 
      sx={props.sx ? props.sx: {mx:2, width: 350}} 
      label={props.label} 
      variant="outlined" 
      value={props.setting.current} 
      onChange={onChange} 
      placeholder={props.label} 
      disabled={props.disabled ? props.disabled: false}
      InputProps={props.InputProps}
    />
  )
}

function TextInferredField(props) {
  return (
    <Link href={props.link} underline="hover">
      <TextField sx={props.sx} label={props.label} variant="outlined" value={props.value} placeholder={props.label} disabled={true} inputProps={{className:"settingExternalLink"}}/>
    </Link>
  )
}



function SettingsPanel(props) {

  const webhook_name = props.dataModel.projectData.webhook_name.current
  const region = props.dataModel.projectData.region.current
  const project_id = props.dataModel.projectData.project_id.current
  const webhook_trigger_uri = `https://${region}-${project_id}.cloudfunctions.net/${webhook_name}`
  const webhook_trigger_uri_link = `https://console.cloud.google.com/functions/details/${region}/${webhook_name}?env=gen1&project=${project_id}&tab=trigger`

  return (
    <div>
      <Grid container rowSpacing={2} direction="column">
        <Grid item justifyContent="flex-start" alignItems="center"> 
          <QueryPrincipal dataModel={props.dataModel}/>
        </Grid>
        <Grid item justifyContent="flex-start" alignItems="center"> 
          <TextInputField label="Project ID" setting={props.dataModel.projectData.project_id}/>
        </Grid>
        <Grid item justifyContent="flex-start" alignItems="center"> 
          <TextInputField label="Region" setting={props.dataModel.projectData.region}/>
        </Grid>
        <Grid item xs={2}> 
          <Divider orientation="horizontal" flexItem/>
        </Grid>

        <Grid item justifyContent="flex-start" alignItems="center"> 
          <TextInputField label="Webhook Name" setting={props.dataModel.projectData.webhook_name} InputProps={{
            endAdornment: (
              <Tooltip title={`Reset to default: ${webhook_name_default}`} disableInteractive arrow placement="right">
                <InputAdornment position="end">
                  <IconButton edge='end' variant="outlined" onClick={(e)=>props.dataModel.projectData.webhook_name.set(webhook_name_default)}>
                    <Replay />
                  </IconButton>
                </InputAdornment>
              </Tooltip>
            ),
          }}
          />
          <TextInferredField sx={{mx:2, width: 800}} label="Trigger URL" dataModel={props.dataModel} link={webhook_trigger_uri_link} value={webhook_trigger_uri}/>
        </Grid>
      </Grid>
    </div>
  );

  // return (
  //   <Box
  //     // sx={{
  //     //   '& > :not(style)': { m: 1, width: '35ch' },
  //     // }}
  //     noValidate
  //     autoComplete="off"
  //   >
  //   <Grid container spacing={24}>
  //   {/* <Grid item xs={4}>
  //     <Paper >Grid cell 1, 1</Paper>
  //   </Grid> */}
  //   <Grid item xs={4}>
  //     <Paper >Grid cell 2, 1</Paper>
  //   </Grid>
  // </Grid>
  // <Grid container spacing={24}>
  //   <Grid item xs={4}>
  //     <Paper >Grid cell 1, 2</Paper>
  //   </Grid>
  //   <Grid item xs={4}>
  //     <Paper >Grid cell 2, 2</Paper>
  //   </Grid>
  // </Grid>
  //     </Box>
  // )

}

export {SettingsPanel}