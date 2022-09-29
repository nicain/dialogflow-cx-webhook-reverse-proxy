import {ServicesPanel, NetworkPanel, AgentPanel, QueryPollAssetStatus, QueryToggleAsset, ServiceDirectoryPanel} from './AssetPollToggle.js'
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import {SettingsPanel} from './SettingsPanel.js';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';
import CircularProgress from '@mui/material/CircularProgress';
import Checkbox from '@mui/material/Checkbox';


function InvertMenuSwitchsCheckbox(props) {

  const stateVar = props.dataModel.invertAssetCollectionSwitches;

  function handleChange () {
    stateVar.set(!stateVar.current)
  }

  return (
    <Checkbox
      checked={stateVar.current}
      onChange={handleChange}
      inputProps={{ 'aria-label': 'controlled' }}
      sx={props.sx}
    />
  );
}

function AssetStatusPanel(props) {

  const TerraformLockedSpinner = props.dataModel.terraformLocked.current ? <CircularProgress size={100} thickness={10}/> : <></>

  return (
    <>
      <Grid container direction='row' alignItems="center" columnSpacing={4}>
      <Grid item>
      <SettingsPanel dataModel={props.dataModel}/>
      </Grid>
      <Grid item>
          {TerraformLockedSpinner}
      </Grid>
      </Grid>

      <Divider sx={{ my:2 }} orientation="horizontal" flexItem/>
      <QueryPollAssetStatus dataModel={props.dataModel}/>

      <Paper variant="string" sx={{width: 370, px:1, py:1, my:1}}>
        <Grid container direction='row' justifyContent="space-between">
          <Typography variant="h5">
            GCP Project Resources:
          </Typography> 
          <QueryToggleAsset target="all" dataModel={props.dataModel} enableAlert={true} includeNameBox={true} isModuleSwitch={true}/>
        </Grid>   
        <Grid container direction='row' justifyContent="space-between" alignItems="center">
          <Typography variant="body1">
          Invert menu switches:
          </Typography> 
          <InvertMenuSwitchsCheckbox dataModel={props.dataModel} sx={{'pr':2}}/>
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