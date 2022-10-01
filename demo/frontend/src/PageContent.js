import Typography from '@mui/material/Typography';
import { StateChangeButtonGrid } from './StateButtonGrid.js'
import { StateImage } from './StateSlides.js'
import { AssetStatusPanel } from './AssetStatusPanel.js'
import { SettingsPanelWithSpinner } from './SettingsPanel.js'
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import {QueryPollAssetStatus} from './AssetPollToggle.js'
import Divider from '@mui/material/Divider';

function HomePage(props) {
  return (
    <Typography paragraph>
      Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
      tempor incididunt ut labore et dolore magna aliqua. Rhoncus dolor purus non
      enim praesent elementum facilisis leo vel. Risus at ultrices mi tempus
      imperdiet. Semper risus in hendrerit gravida rutrum quisque non tellus.
      Convallis convallis tellus id interdum velit laoreet id donec ultrices.
      Odio morbi quis commodo odio aenean sed adipiscing. Amet nisl suscipit
      adipiscing bibendum est ultricies integer quis. Cursus euismod quis viverra
      nibh cras. Metus vulputate eu scelerisque felis imperdiet proin fermentum
      leo. Mauris commodo quis imperdiet massa tincidunt. Cras tincidunt lobortis
      feugiat vivamus at augue. At augue eget arcu dictum varius duis at
      consectetur lorem. Velit sed ullamcorper morbi tincidunt. Lorem donec massa
      sapien faucibus et molestie ac.
    </Typography>
  )
}

function StateButtonGridAndImage(props) {
  return (
    <Grid container direction='row' columnSpacing={3} alignItems="center" justifyContent="center" >
      <Grid item>
        <StateChangeButtonGrid dataModel={props.dataModel} liveMode={props.liveMode}/>
      </Grid>
      <Grid item>
        <StateImage dataModel={props.dataModel}/>
      </Grid>
    </Grid>
  )
}

function TutorialPage(props) {
  return (
    <>
      <Typography paragraph>
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
        tempor incididunt ut labore et dolore magna aliqua. Rhoncus dolor purus non
        enim praesent elementum facilisis leo vel. Risus at ultrices mi tempus
        imperdiet. Semper risus in hendrerit gravida rutrum quisque non tellus.
        Convallis convallis tellus id interdum velit laoreet id donec ultrices.
        Odio morbi quis commodo odio aenean sed adipiscing. Amet nisl suscipit
        adipiscing bibendum est ultricies integer quis. Cursus euismod quis viverra
        nibh cras. Metus vulputate eu scelerisque felis imperdiet proin fermentum
        leo. Mauris commodo quis imperdiet massa tincidunt. Cras tincidunt lobortis
        feugiat vivamus at augue. At augue eget arcu dictum varius duis at
        consectetur lorem. Velit sed ullamcorper morbi tincidunt. Lorem donec massa
        sapien faucibus et molestie ac.
      </Typography>
      <StateButtonGridAndImage dataModel={props.dataModel} liveMode={false}/>
    </>
  )
}

function LiveDemoPage(props) {
  return (
    <>
      <QueryPollAssetStatus dataModel={props.dataModel}/>
      <Typography paragraph>
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
        tempor incididunt ut labore et dolore magna aliqua. Rhoncus dolor purus non
        enim praesent elementum facilisis leo vel. Risus at ultrices mi tempus
        imperdiet. Semper risus in hendrerit gravida rutrum quisque non tellus.
        Convallis convallis tellus id interdum velit laoreet id donec ultrices.
        Odio morbi quis commodo odio aenean sed adipiscing. Amet nisl suscipit
        adipiscing bibendum est ultricies integer quis. Cursus euismod quis viverra
        nibh cras. Metus vulputate eu scelerisque felis imperdiet proin fermentum
        leo. Mauris commodo quis imperdiet massa tincidunt. Cras tincidunt lobortis
        feugiat vivamus at augue. At augue eget arcu dictum varius duis at
        consectetur lorem. Velit sed ullamcorper morbi tincidunt. Lorem donec massa
        sapien faucibus et molestie ac.
      </Typography>
      <StateButtonGridAndImage dataModel={props.dataModel} liveMode={true}/>
      <Divider sx={{ my:2 }} orientation="horizontal" flexItem/>
      <SettingsPanelWithSpinner dataModel={props.dataModel}/>
      <Divider sx={{ my:2 }} orientation="horizontal" flexItem/>
      <AssetStatusPanel dataModel={props.dataModel}/>
    </>
  )
}

function PageContent(props) {
  const pageNumber = props.dataModel.activePage.current
  if (pageNumber === 0) {
    return <HomePage dataModel={props.dataModel}/>
  } else if (pageNumber === 1) {
    return <TutorialPage dataModel={props.dataModel}/>
  } else if (pageNumber === 2) {
    return <LiveDemoPage dataModel={props.dataModel}/>
  }
}

export {PageContent}