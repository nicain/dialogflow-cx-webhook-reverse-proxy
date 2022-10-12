import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';

function TutorialPageIntroduction(props) {
  return (
    <Paper sx={{ width: '75%', ml:2}} variant="string">
      <Typography variant="h3" sx={{my:3 }}>Securing Your Dialogflow Agent: A Tutorial</Typography>
      <Typography paragraph>
        The front-line security for a Dialogflow CX agent is fairly straight-forward to implement, and accomplished through Access Controls via Identity and Access Managament (IAM) roles. For self-contained agents or exploratory development, these measures provide more than enough flexibility and safety. The true power of Dialogflow is unlocked, however, when enabling webhook fullfillments to other resources, such as databases or other business-logic implemented in on external servers or via serverless applications. In these scenarios, additional layers of security may not only be a good idea, but required for regulatory compliance. 
      </Typography>
      <Typography paragraph>
        What other options does Google Cloud Platform (GCP) provide for securing sensitive servers or application layers from unexpected or malicious intrusion? A "defense-in-depth" approach to security suggests building multiple layers of security into the system architure. With more layers, however, come more configurations and complications to design and manage; below is an interactve tutorial aimed to understanding how IAM permissions, firewall configurations, custom Certificate Authority (CA) certificates, and VPC Service Controls can be layered to secure sensitive data.
      </Typography>
    </Paper>
  )
}

export {TutorialPageIntroduction}