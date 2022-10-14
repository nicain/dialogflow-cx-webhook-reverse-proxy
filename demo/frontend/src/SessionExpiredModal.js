import Box from '@mui/material/Box';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';

const style = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: 400,
  bgcolor: 'background.paper',
  border: '2px solid #000',
  boxShadow: 24,
  p: 4,
};

function SessionExpiredModal(props) {


  function handleClose() {
    props.dataModel.sessionExpiredModalOpen.set(false);
  }
  const queryStr = new URLSearchParams(props.dataModel.queryParams).toString();
  return (
    <Modal
      open={props.dataModel.sessionExpiredModalOpen.current}
      onClose={handleClose}
    >
      <Box sx={style}>
        <Typography variant="h6" component="h2">
          Authenticated Session Expired
        </Typography>
        <Typography sx={{ mt: 2 }}>
          Please re-login to continue.
        </Typography>
        <Button onClick={handleClose} href={`http://${window.location.host}/session?${queryStr}`}>OK</Button>
      </Box>
    </Modal>
  )
}

export {SessionExpiredModal}