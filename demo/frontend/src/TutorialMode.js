import Switch from '@mui/material/Switch';

function StatusTutorialMode(props) {
  return (<div>{(props.state.status) ? "True" : "False"}</div>);
}

function ToggleStatusTutorialMode(props) {

  function onChange() {
    props.state.setStatus(!props.state.status)
  }

  return (
    <>
      {<Switch
        onChange={onChange} 
        checked={typeof(props.state.status) == "boolean" ? props.state.status : false}
        color="primary"
      />}
    </>
  )
}

export {StatusTutorialMode, ToggleStatusTutorialMode}