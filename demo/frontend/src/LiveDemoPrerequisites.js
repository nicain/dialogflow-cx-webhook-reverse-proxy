import Typography from '@mui/material/Typography';
import {SnippetWithCopyButton} from './SnippetWithCopyButton.js'
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Link from '@mui/material/Link';
import locationSettingsImage from "./location_settings.png";
import Divider from '@mui/material/Divider';

function LiveDemoPrerequisites() {

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

  return (
    <Paper sx={{ width: '75%', ml:2}} variant="string">
      <Typography variant="h3" sx={{my:3 }}>
        Live Demo:
      </Typography>

      <Typography paragraph sx={{ ml:2 }}>
        After walking through the Tutorials pages to gain a better understanding of how different configurations can improve the security of a webhook-enabled Dialogflow CX agent, it's time to try it for yourself. 
      </Typography>

      <Divider sx={{ my:1 }} orientation="horizontal" flexItem/>
      <Typography variant="h4" sx={{my:3 }}>
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
        title='Create New Project (No Organization)' 
        code={(
          "gcloud projects create ${project_id}"+"\n"+
          "gcloud beta billing projects link ${project_id} --billing-account ${account_id}"
        )}
      />
      <Typography paragraph sx={{ ml:2 }}>
        If you would like to configure VPC Service Controls (VPC-SC) for your demo project, it must reside in a {GCPOrganization} and be configured as {withinScope} of a VPC-SC Access Policy for its Organization. If you do not have sufficient permissions ({policyEditor}) within your organization, contact your Organization Administrator to create and configure a policy for you after you create the project: 
      </Typography>
      <SnippetWithCopyButton 
        title='Create New Project' 
        code={(
          "gcloud projects create ${project_id} --organization=${organization_id}"+"\n"+
          "gcloud beta billing projects link ${project_id} --billing-account ${account_id}"
        )}
      />

      <Typography variant="h5" sx={{my:3 }}>Step 2: Enable Dialogflow Location Settings</Typography>
      <Typography paragraph sx={{ ml:2 }}>
      Dialogflow Location Settings are required for using a regionalized Dialogflow agent because a regional agent is required for Service Directory webhook integration. More details on regionalization and Location settings for Dialogflow CX agents are {locationSettings}. To configure Location settings, click “Location settings” from the {agentSelectorInterface}, and select “Configure” for region “us-central1” (the default region for this demo).
      </Typography>
      <Box
        component="img"
        src={locationSettingsImage}
        alt="Location Settings"
        sx={{ maxWidth:'400px', minWidth:'30%', my:2, py:0, ml:4, justifyContent:"flex-start" }} />

      <Typography variant="h5" sx={{my:3 }}>Step 3: Log In</Typography>
      <Typography paragraph sx={{ ml:2 }}>
        The Status Dashboard and Deployment Dashboard (below) uses a securely stored access token to deploy and update GCP resources on your behalf. To enable this workflow, you will need to log in using the button on the Navigation Sidebar, or the “Principal” dialog box in the Settings Dashboard (also below). This token will expire after one hour, so you may need to periodically re-authenticate the service. You can manually logout via these same menus, otherwise you will be logged-out automatically once the token expires.
      </Typography>
    </Paper>
  )
}

export {LiveDemoPrerequisites}