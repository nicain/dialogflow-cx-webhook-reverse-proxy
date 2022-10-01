import Checkbox from '@mui/material/Checkbox';

function InvertMenuSwitchesCheckbox(props) {

  const stateVar = props.dataModel.invertAssetCollectionSwitches;

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

export {InvertMenuSwitchesCheckbox}