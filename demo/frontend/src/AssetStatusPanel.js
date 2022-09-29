import {ServicesPanel, NetworkPanel, AgentPanel, QueryPollAssetStatus, QueryToggleAsset, ServiceDirectoryPanel} from './AssetPollToggle.js'
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import {SettingsPanel} from './SettingsPanel.js';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';

function AssetStatusPanel(props) {
  return (
    <>
      <SettingsPanel dataModel={props.dataModel}/>
      <Divider sx={{ my:2 }} orientation="horizontal" flexItem/>
      <QueryPollAssetStatus dataModel={props.dataModel}/>


      <Paper variant="string" sx={{width: 370, px:1, py:1, my:1}}>
        <Grid container direction='row' justifyContent="space-between">
          <Typography variant="h5">
            GCP Project Resources:
          </Typography> 
          <QueryToggleAsset target="all" dataModel={props.dataModel} enableAlert={true} includeNameBox={true}/>
        </Grid>     
      </Paper>


      <Grid container direction='row' columnSpacing={3} justifyContent="flex-start" alignItems="top">
        <Grid item>
          <Paper variant="outlined" sx={{width: 370, px:1, py:1, my:1}}>
            <ServicesPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={{width: 370, px:1, py:1, my:1}}>
            <NetworkPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={{width: 370, px:1, py:1, my:1}}>
            <ServiceDirectoryPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={{width: 370, px:1, py:1, my:1}}>
            <AgentPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
      </Grid>
    </>
  )
}

export {AssetStatusPanel}