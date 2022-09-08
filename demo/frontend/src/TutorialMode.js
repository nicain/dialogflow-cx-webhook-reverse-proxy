import Switch from '@mui/material/Switch';

function StatusTutorialMode(props) {
  return (<div>{(props.state.status.current) ? "True" : "False"}</div>);
}

function ToggleStatusTutorialMode(props) {

  function onChange() {
    props.state.status.set(!props.state.status.current)
  }

  return (
    <>
      {<Switch
        onChange={onChange} 
        checked={typeof(props.state.status.current) == "boolean" ? props.state.status.current : false}
        color="primary"
      />}
    </>
  )
}

export {StatusTutorialMode, ToggleStatusTutorialMode}