import {ServicesPanel, NetworkPanel, AgentPanel, ServiceDirectoryPanel, ServicePerimeterPanel, PANEL_WIDTH} from './AssetPollToggle.js'
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';


function AssetStatusPanel(props) {

  const sx = {
    height:500,
    width: PANEL_WIDTH+100,
    px:1,
    py:1,
    my:1,
  }

  var ServicesPanelObj
  if (props.dataModel.showServicesPanel.current) {
    ServicesPanelObj = (
      <Grid item>
        <Paper variant="outlined" sx={sx}>
          <ServicesPanel dataModel={props.dataModel}/>
        </Paper>
      </Grid>
    )
  } else {
    ServicesPanelObj = <></>
  }

  return (
    <>
      <Grid container direction='row' columnSpacing={3} alignItems="flex-start">
        <Grid item>
          <Paper variant="outlined" sx={sx}>
            <NetworkPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={sx}>
            <ServiceDirectoryPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={sx}>
            <AgentPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        <Grid item>
          <Paper variant="outlined" sx={sx}>
            <ServicePerimeterPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>
        {ServicesPanelObj}
      </Grid>
    </>
  )
}

export {AssetStatusPanel}