import {ServicesPanel, NetworkPanel, AgentPanel, ServiceDirectoryPanel, PANEL_WIDTH} from './AssetPollToggle.js'
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';


function AssetStatusPanel(props) {

  const sx_1 = {
    height:600,
    width: PANEL_WIDTH+100,
    px:1,
    py:1,
    my:1,
  }

  const sx_2 = {
    height:292,
    width: PANEL_WIDTH+100,
    px:1,
    py:1,
    my:1,
  }

  var ServicesPanelObj
  if (props.dataModel.showServicesPanel.current) {
    ServicesPanelObj = (
      <Grid item>
        <Paper variant="outlined" sx={sx_1}>
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
          <Paper variant="outlined" sx={sx_1}>
            <NetworkPanel dataModel={props.dataModel}/>
          </Paper>
        </Grid>

        <Grid item>
          <Grid container direction='column'>
            <Grid item>
              <Paper variant="outlined" sx={sx_2}>
                <ServiceDirectoryPanel dataModel={props.dataModel}/>
              </Paper>
            </Grid>
            <Grid item>
              <Paper variant="outlined" sx={sx_2}>
                <AgentPanel dataModel={props.dataModel}/>
              </Paper>
            </Grid>
          </Grid>
        </Grid>


        {ServicesPanelObj}
      </Grid>
    </>
  )
}

export {AssetStatusPanel}