import {ServicesPanel, NetworkPanel, AgentPanel, QueryPollAssetStatus} from './AssetPollToggle.js'
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import {SettingsPanel} from './SettingsPanel.js';
import Divider from '@mui/material/Divider';

function AssetStatusPanel(props) {
  return (
    <>
      <SettingsPanel dataModel={props.dataModel}/>
      <Divider sx={{ my:2 }} orientation="horizontal" flexItem/>
      <QueryPollAssetStatus dataModel={props.dataModel}/>
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
            <AgentPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
      </Grid>
    </>
  )
}

export {AssetStatusPanel}