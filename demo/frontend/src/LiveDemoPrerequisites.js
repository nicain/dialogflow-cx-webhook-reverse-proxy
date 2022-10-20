import Typography from '@mui/material/Typography';
import {SnippetWithCopyButton} from './SnippetWithCopyButton.js'
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Link from '@mui/material/Link';
import locationSettingsImage from "./location_settings.png";
import Divider from '@mui/material/Divider';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';


function LiveDemoPrerequisites(props) {

  const newToGCPInstructions = <Link
    target="_blank"
    href="https://cloud.google.com/resource-manager/docs/creating-managing-projects"
    variant="body1">
      these instructions
    </Link>;

  const cloudBilling = <Link
    target="_blank"
    href="https://cloud.google.com/billing/docs/how-to/modify-project"
    variant="body1">
      Cloud Billing
    </Link>;

  const freeTrialCredits = <Link
    target="_blank"
    href="https://cloud.google.com/free"
    variant="body1">
      Free trial credits
    </Link>;

  const GCPOrganization = <Link
    target="_blank"
    href="https://cloud.google.com/resource-manager/docs/creating-managing-organization"
    variant="body1">
      GCP Organization
    </Link>;

  const withinScope = <Link
    target="_blank"
    href="https://cloud.google.com/vpc-service-controls/docs/manage-policies"
    variant="body1">
      within-scope
    </Link>;
  const policyEditor = <Link
    target="_blank"
    href="https://cloud.google.com/access-context-manager/docs/access-control#required-roles"
    variant="body1">
      roles/accesscontextmanager.policyEditor
    </Link>;
  const locationSettings = <Link
    target="_blank"
    href="https://cloud.google.com/dialogflow/cx/docs/concept/region#location-settings"
    variant="body1">
      available here
    </Link>;
  const agentSelectorInterface = <Link
    target="_blank"
    href="https://cloud.google.com/dialogflow/cx/docs/concept/console#agent"
    variant="body1">
      agent selector interface
    </Link>;
  const apiConsole = <Link
    target="_blank"
    href="https://console.cloud.google.com/apis/dashboard?"
    variant="body1">
      "APIs & Services" menu in the Google Cloud Console
    </Link>;
  const terraformLink = <Link
    target="_blank"
    href="https://www.terraform.io/"
    variant="body1">
      Terraform
    </Link>;
  const setUpOrgPolicy = <Link
    target="_blank"
    href="https://cloud.google.com/functions/docs/securing/using-vpc-service-controls#set_up_organization_policies"
    variant="body1">
      set up organization policies
    </Link>;
  const accessPolicyInstructions = <Link
    target="_blank"
    href="https://cloud.google.com/access-context-manager/docs/create-access-policy"
    variant="body1">
      Additional instructions are available here
    </Link>;

  return (
    <Paper sx={{ width: '85%', ml:2}} variant="string">
      <Typography variant="h3" sx={{my:3 }}>
        Launch Pad: Live Demo
      </Typography>
      <Typography paragraph sx={{ ml:2, mb:0}}>
        After working through the <Link style={{cursor:"pointer"}} onClick={()=>{props.dataModel.activePage.set('tutorial')}}>Tutorials</Link> pages to gain a better understanding of how different configurations can improve the security of a webhook-enabled Dialogflow CX agent, it's time to try it for yourself with a Live Demo that is fully under your control. This page contains three main sections to 
      </Typography>
      <List sx={{ml:6}}>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <Link href='#beforeYouBegin'><ListItemText primary="Before you Begin: Prerequisites"/></Link>
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <Link href='#statusDashboard'><ListItemText primary="Status Dashboard"/></Link>
        </ListItem>
        <ListItem  style={{ display: 'list-item', padding:0,listStyleType: "disc", }}>
          <Link href='#deploymentDashboard'><ListItemText primary="Deployment Dashboard"/></Link>
        </ListItem>
      </List>
      <Typography paragraph sx={{ ml:2 }}>
        The goal of the Live Demo Launch Pad is to simplify the process of configuring all of the resources necessary for a Dialogflow Agent with a Cloud Functions webhook. The deployment dashboard uses {terraformLink} to deploy and configure all of these resources on your behalf into a project that you own (your "Home Project"), to that you can immediately jump in and investage how all of the components work together. Any dependencies or preconditions that are necessary to deploy the Dialogflow Agent are inferred and handled automatically (with a few exceptions; see <Link href='#deploymentDashboard'>"Before you Begin: Prerequisites"</Link>).
      </Typography>

      <Typography paragraph sx={{ ml:2 }}>
        <Box sx={{ fontWeight: 'bold' }}> Basic Deployment </Box>The <Link href='#statusDashboard'>Status Dashboard</Link> is identical to the Tutorial Panel, except enabling the slides on this page will update the Terraform-controlled resources in your Home Project. Once you are ready to begin, you can head to the <Link href='#deploymentDashboard'>Deployment Dashboard</Link> to get started. If you want to start with only the Dialogflow Agent with Webhook Fulfillment, click on the "Dialogflow Agent" slider in the "Webhook Agent" menu. This will also deploy the Cloud Function that fulfills the webhook, and update the agent to target that functions URI. The links to the left of each slider will open the resource in the GCP Console.
      </Typography>

      <Typography paragraph sx={{ ml:2 }}>
      <Box sx={{ fontWeight: 'bold' }}> Advanced: VPC Proxy Server </Box> To deploy a VPC reverse proxy server, and redirect traffic via mTLS (self-signed certificates), enable the "VPC Resources" and "Service Directory" sliders in the <Link href='#deploymentDashboard'>Deployment Dashboard</Link>. This might take some time, so be patient until the spinning "Refreshing State..." indicator is complete. After this, you will be able to redirect traffic through the VPC by selecting the "Route Dialogflow Through VPC Proxy?" toggle in the <Link href='#statusDashboard'>Status Dashboard</Link>. If you do not have an Access Policy Title configured in the input box, the "Service Perimeter" slider will not deploy—a policy is a prerequisite for this resource (See <Link href='#step4ConfigureAccessPolicy'>Step 4 (Optional): Configure your Access Policy</Link>, and "Advanced: VPC Service Controls" below for more information).
      </Typography>

      <Typography paragraph sx={{ ml:2 }}>
      <Box sx={{ fontWeight: 'bold' }}> Advanced: VPC Service Controls (VPC-SC)</Box> For the most secure deployment, you will need to provide an Access Policy Title in Depoyment Dashboard. The first prerequisite step is that your Home Project must be configured inside an Organization; policies are configured with for at the Organization level, so if you do not have sufficient permission to {setUpOrgPolicy} you will need to contact an Administrator and have one assigned, which includes your project_id as in-scope. If your username already has sufficient permissions, a policy will be made for your service perimeter. Once the perimieter is configured, the "Service Perimeter" slider in the "Service Directory" menu will unlock, so that you can Restrict VPC-SC protected services (Dialogflow and Cloud Functions) from the <Link href='#statusDashboard'>Status Dashboard</Link>.
      </Typography>


      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Typography variant="h4" sx={{my:3 }} id="beforeYouBegin">
        Before you Begin: Prerequisites
      </Typography>

      <Typography paragraph sx={{ ml:2 }}>
        Before you begin, you will need to take a few minutes to authorize Terraform to deploy some Google Cloud Platform (GCP) resources on your behalf, and select (or set up) a Home Project to contain them. 
      </Typography>

      <Typography variant="h5" sx={{my:3 }}>Step 1: Create a Home Project</Typography>
      <Typography paragraph sx={{ ml:2 }}>
        If you are new to Google Cloud Platform, {newToGCPInstructions} will guide you through the process of creating your first project. Some resources necessary for the demo (VPC Service Controls, and Dialogflow) fall outside the Free Usage tier, so you will need to enable billing for that project with {cloudBilling}. {freeTrialCredits} are available for new users to help get you started. 
      </Typography>
      <SnippetWithCopyButton 
        language="bash"
        title='Create New Project (No Organization)' 
        code={(
          "gcloud projects create ${project_id}"+"\n"+
          "gcloud beta billing projects link ${project_id} --billing-account ${account_id}"+"\n"+
          "gcloud config set project ${project_id}"
        )}
      />
      <Typography paragraph sx={{ ml:2 }}>
        If you would like to configure VPC Service Controls (VPC-SC) for your demo project, it must reside in a {GCPOrganization} and be configured as {withinScope} of a VPC-SC Access Policy for its Organization. If you do not have sufficient permissions ({policyEditor}) within your organization, contact your Organization Administrator to create and configure a policy for you after you create the project: 
      </Typography>
      <SnippetWithCopyButton
        language="bash"
        title='Create New Project' 
        code={(
          "gcloud projects create ${project_id} --organization=${organization_id}"+"\n"+
          "gcloud beta billing projects link ${project_id} --billing-account ${account_id}"+"\n"+
          "gcloud config set project ${project_id}"
        )}
      />

      <Typography variant="h5" sx={{my:3 }}>Step 2: Enable Cloud Resource Manager API</Typography>
      <Typography paragraph sx={{ ml:2 }}>
        The Cloud Resource Manager API is a necessary one-time enablement that allows Terraform to deploy (and remove) resources into your project on your behalf. To enable the API, visit the {apiConsole}, or use the gcloud CLI:
      </Typography>
      <SnippetWithCopyButton
        language="bash"
        title='Enable Cloud Resource Manager API' 
        code={(
          "gcloud auth login ${principal}"+"\n"+
          "gcloud config set project ${project_id}"+"\n"+
          "gcloud services enable cloudresourcemanager.googleapis.com"
        )}
      />

      <Typography variant="h5" sx={{my:3 }}>Step 3: Enable Dialogflow Location Settings</Typography>
      <Typography paragraph sx={{ ml:2 }}>
      Dialogflow Location Settings are required for using a regionalized Dialogflow agent because a regional agent is required for Service Directory webhook integration. More details on regionalization and Location settings for Dialogflow CX agents are {locationSettings}. To configure Location settings, click “Location settings” from the {agentSelectorInterface}, and select “Configure” for region “us-central1” (the default region for this demo).
      </Typography>
      <Paper
        component="img"
        src={locationSettingsImage}
        alt="Location Settings"
        sx={{ maxWidth:'500px', minWidth:'30%', my:2, px:2, py:2, ml:4, justifyContent:"flex-start" }} />

      <Typography variant="h5" sx={{my:3 }} id="step4ConfigureAccessPolicy">Step 4 (Optional): Configure your Access Policy</Typography>
      <Typography paragraph sx={{ ml:2 }}>
        Using VPC Security Controls inside of your Home Project requires an Access Policy to be obtained, with your project_id assigned as "in-scope" for the project. If your account does not have these permissions, please ask your Organization Administrator to configure this for you ({accessPolicyInstructions}). Once you policy is created, you will be able to get the title of the policy from the GCP Console, or by using the gcloud CLI:
        <SnippetWithCopyButton
          language="bash"
          title='Get Access Policy Title' 
          code={(
            "gcloud access-context-manager policies list --organization ${organization_id}"
          )}
        />

        
      </Typography>

      <Typography variant="h5" sx={{my:3 }}>Step 5: Log In</Typography>
      <Typography paragraph sx={{ ml:2 }}>
        The <Link href='#statusDashboard'>Status Dashboard</Link> and <Link href='#deploymentDashboard'>Deployment Dashboard</Link> (below) use a securely stored access token to deploy and update GCP resources on your behalf. To enable this workflow, you will need to log in using the button on the Navigation Sidebar, or the “Principal” dialog box in the Deployment Dashboard (also below). This token will expire after one hour, so you may need to periodically re-authenticate the service. You can manually logout via these same menus, otherwise you will be logged-out automatically once the token expires.
      </Typography>
    </Paper>
  )
}

export {LiveDemoPrerequisites}