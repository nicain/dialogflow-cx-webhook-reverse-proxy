import uuid

import google.cloud.dialogflowcx as cx
import google.auth

def ping_agent():

  credentials, project = google.auth.default()
  location = 'us-central1'
  language_code = 'en'
  client_options = {"api_endpoint": f"{location}-dialogflow.googleapis.com"}


  request = cx.ListAgentsRequest(parent = f"projects/{project}/locations/us-central1")
  client = cx.AgentsClient(
    client_options=client_options,
    credentials=credentials,
  )
  agent_dict = {agent.display_name:agent for agent in client.list_agents(request=request)}
  agent = agent_dict["Telecommunications"]


  client = cx.FlowsClient(
    client_options=client_options,
    credentials=credentials,
  )
  request = cx.ListFlowsRequest(
      parent=agent.name,
  )
  flows_dict = {flow.display_name:flow for flow in client.list_flows(request=request)}
  flow = flows_dict['Cruise Plan']

  client = cx.PagesClient(
    client_options=client_options,
    credentials=credentials,
  )
  pages = {page.display_name:page for page in client.list_pages(parent=flow.name)}
  page = pages['Collect Customer Line']


  text = '123456'
  session_id = str(uuid.uuid1())
  request = cx.DetectIntentRequest(
      session=f"{agent.name}/sessions/{session_id}",
      query_input=cx.QueryInput(
          text=cx.TextInput(
              text=text,
          ),
          language_code=language_code,
      ),
      query_params=cx.QueryParameters(
          current_page=page.name,
      ),
  )
  client = cx.SessionsClient(
    client_options=client_options,
    credentials=credentials,
  )
  response = client.detect_intent(request)
  response_messages = response.query_result.response_messages
  parameters = response.query_result.parameters
  return response_message.text.text[0]
