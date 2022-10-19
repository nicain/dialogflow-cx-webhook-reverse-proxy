import Typography from '@mui/material/Typography';
import {useState} from "react";
import Link from '@mui/material/Link';
import Paper from '@mui/material/Paper';
import { ArchitectureImage } from './StateSlides.js'
import Grid from '@mui/material/Grid';
import arrowImage from "./arrow.png";
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Divider from '@mui/material/Divider';

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

  const webhookIntegrationQuickstart = <Link
  target="_blank"
  href="https://cloud.google.com/dialogflow/cx/docs/quick/webhook"
  variant="body1">
    Quickstart
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
        Dialogflow CX enables users to design rich, intuitive flows for interactive conversational agents. With many {powerfulFeatures}, Dialogflow CX agents can handle user interactions ranging from simple requests for scripted information, to detailed interactive responses capable of integrating external data sources and models. The main mechanism to achieve these advanced use cases is through its  {webhookIntegration}. The purpose of this Tutorial and Live Demo site is to provide information (and a working example) of Dialogflow with Webhooks for advanced users, as their use-case scales up from early exploratoration to a production deployment with a virtual private cloud (VPC).
      </Typography>
      <List sx={{ml:6}}>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <Link style={{cursor:"pointer"}} onClick={()=>{props.dataModel.activePage.set('tutorial')}}>
            <ListItemText primary="Tutorial"/>
          </Link>
          <Typography paragraph>
            Explore different deployment scenarios ranging across use cases from exploration/proof-of-concept to production deployement. See how different security strategies affect the complexity of the deployment including IAM permissions, Ingress/Firewall protections, mTLS authentication, and VPC Service Controls.
          </Typography>
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <Link style={{cursor:"pointer"}} onClick={()=>{props.dataModel.activePage.set('liveDemo')}}>
            <ListItemText primary="Live Demo"/>
          </Link>
          <Typography paragraph>
            Use Terraform to easily deploy these user scenarios into a project that you control. Use links in the "Deployment Dashboard" to view all of the required resources in your project, and the Status Dashbord to update their configuration to explore how changes to the security strategy alter the resources.
          </Typography>
        </ListItem>
      </List>
      <Typography paragraph sx={{pt:2, pb:0, mb:0}}>
        These resources assume previous familiarity with Dialogflow CX, Cloud Functions, and VPC Service Controls . If you have never used these products before, this {webhookIntegrationQuickstart} can provide an introduction. 
      </Typography>

      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Typography variant="h4" sx={{my:3 }}>
        Transitioning to a Production Deployment
      </Typography>
      <Typography paragraph sx={{pt:2, pb:0, mb:0}}>
        When transitioning from exploration or proof-of-concept to a production deployment, securing business-critical information or satisfying compliance/regulatory constraints becomes a main concern. The Tutorial section shows how multiple layers of security can be overlapped to implement a "defense-in-depth" strategy, so that if one layer fails, additional layers can still ensure that sensitive data remains secure. These strategies include:
      </Typography>
      <List sx={{ml:6}}>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <ListItemText 
            primary="IAM permissions secure webhook invocation to only intended users" 
          />
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <ListItemText 
            primary="Webhook ingress settings block invocation from outside the VPC" 
          />
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <ListItemText 
            primary="VPC Service Control perimeters block API access to sensitive resources" 
          />
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <ListItemText 
            primary="A VPC proxy server enforces mTLS authentication with Dialogflow and provides fine-grained firewall protection within the VPC" 
          />
        </ListItem>
      </List>
      <Grid container direction='row' columnSpacing={3} alignItems="center" justifyContent="space-around" >
        <Grid item>
          <Grid container direction='column' alignItems="center" justifyContent="center">
            <ArchitectureImage renderedPageNumber={StaticPage[1]} currPage={32} pageHeight={200} width={470}/>
            <Typography variant="h7">
              Proof-of-Concept
            </Typography>
          </Grid>
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
          <Grid container direction='column' alignItems="center" justifyContent="center">
            <ArchitectureImage renderedPageNumber={StaticPage[0]} currPage={1} pageHeight={200} width={470}/>
            <Typography variant="h7">
              Production
            </Typography>
          </Grid>
        </Grid>
      </Grid>

      <Typography paragraph sx={{my:3 }}>
        The images above illustrate opposite ends of this spectrum. The diagram on the left depicts a "proof-of-concept" resource architecture, with two main components: A Dialogflow CX Agent which communicates via a webhook to a Cloud Function. While self-contained in this diagram, the business logic necessary to fulfill the webhook request might not be fully encapsulated by the Cloud Function, requiring further egress to other services such as BigQuery or Cloud Storage. No security layers are implemented in this scenario, allowing ingress to Dialogflow for all authenticated users, and to Cloud Functions for all users (authenticated or not, represented by the 4 "User" icons with the blocked-key indicating unauthenticated).
      </Typography>
      <Typography paragraph>
        The diagram on the right adds several additional resources and configurations to the deployment: IAM and ingress protections on the Cloud Function, two VPC-SC service perimeters and a reverse proxy server running in Google Compute Engine (GCE). The service perimeters are represented by the red bands around the Dialogflow CX resource group and the Cloud Functions resource group, and indicate that external access to these service APIs is blocked. The VPC resource block contains the GCE instance functioning as a reverse proxy server.
      </Typography>


      <Typography variant="h5" sx={{my:3, ml:2}}>
        Securing Webhooks with IAM Permissions
      </Typography>
      <Typography paragraph>
        TODO
      </Typography>
  
      <Typography variant="h5" sx={{my:3, ml:2}}>
        Securing APIs: VPC Service Control Perimeters
      </Typography>
      <Typography paragraph>
        TODO
      </Typography>

      <Typography variant="h5" sx={{my:3, ml:2}}>
        Securing Webhooks with Webhook Ingress from VPC 
      </Typography>
      <Typography paragraph>
        TODO
      </Typography>
      





    </Paper>
  )
}

export {HomePage}