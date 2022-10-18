import Typography from '@mui/material/Typography';
import {useState} from "react";
import Link from '@mui/material/Link';
import Paper from '@mui/material/Paper';
import { ArchitectureImage } from './StateSlides.js'
import Grid from '@mui/material/Grid';
import arrowImage from "./arrow.png";

function HomePage(props) {

  const powerfulFeatures = <Link
    target="_blank"
    href="https://cloud.google.com/dialogflow#section-2"
    variant="body1">
      powerful features
    </Link>;
  
  const webhookIntegration = <Link
  target="_blank"
  href="https://cloud.google.com/dialogflow#section-2"
  variant="body1">
    webhook integration
  </Link>;
  
  const StaticPage = [{current: null, set: null}, {current: null, set: null}];
  [StaticPage[0].current, StaticPage[0].set] =  useState(null);
  [StaticPage[1].current, StaticPage[1].set] =  useState(null);

  return (
    <Paper sx={{ width: '85%', ml:2}} variant="string">
      <Typography variant="h3" sx={{my:3 }}>
        Dialogflow CX with Webhook Fulfillment:
      </Typography>
      <Typography variant="h4" sx={{my:3 }}>
        Tutorial and Live Demo
      </Typography>
      <Typography paragraph>
        Dialogflow CX enables users to design rich, intuitive flows for interactive conversational agents. With many {powerfulFeatures}, Dialogflow CX agents can handle user interactions ranging from simple requests for scripted information, to detailed interactive responses capable of integrating external data sources and models. The main mechanism to achieve these advanced use cases is through its  {webhookIntegration}. The purpose of this Tutorial and Live Demo site is to provide information (and a working example) of Dialogflow with Webhooks for advanced users, as their use-case scales up from early exploratoration to a production deployment.
      </Typography>

      <Typography variant="h4" sx={{my:3 }}>
        Dialogflow in Production
      </Typography>
      <Typography paragraph>
        When transitioning from exploration or proof-of-concept to a production deployment, security becomes one of the main concerns for a business-critical 
      </Typography>


      <Grid container direction='row' columnSpacing={3} alignItems="center" justifyContent="space-around" >
        <Grid item>
          <ArchitectureImage renderedPageNumber={StaticPage[1]} currPage={32} pageHeight={200} width={470}/>
        </Grid>
        <Grid item>
          <Paper
            component="img"
            src={arrowImage}
            alt="Arrow"
            variant="string"
            sx={{ pl:2, width:100}} 
          />
        </Grid>
        <Grid item>
          <ArchitectureImage renderedPageNumber={StaticPage[0]} currPage={1} pageHeight={200} width={470}/>
        </Grid>
      </Grid>



    </Paper>
    
  )
}

export {HomePage}