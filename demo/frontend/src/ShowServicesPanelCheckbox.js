import Checkbox from '@mui/material/Checkbox';

function ShowServicesPanelCheckbox(props) {

  const stateVar = props.dataModel.showServicesPanel;

  function handleChange () {
    stateVar.set(!stateVar.current)
  }

  return (
    <Checkbox
      checked={stateVar.current}
      onChange={handleChange}
      inputProps={{ 'aria-label': 'controlled' }}
      sx={props.sx}
    />
  );
}

export {ShowServicesPanelCheckbox}