import { useState } from "react";
import { IconButton, Snackbar } from "@mui/material";
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import SyntaxHighlighter from 'react-syntax-highlighter';

const CopyToClipboardButton = (props) => {
  const [open, setOpen] = useState(false);

  const handleClick = () => {
    setOpen(true);
    navigator.clipboard.writeText(props.text);
  };

  return (
    <>
      <IconButton onClick={handleClick} color="primary">
        <ContentCopyIcon />
      </IconButton>
      <Snackbar
        message="Copied to clibboard"
        anchorOrigin={{ vertical: "top", horizontal: "center" }}
        autoHideDuration={2000}
        onClose={() => setOpen(false)}
        open={open}
      />
    </>
  );
};

function SnippetWithCopyButton(props) {
  return (
    <Card sx={{ maxWidth:'700px', minWidth:'70%', my:2, py:0, ml:2, justifyContent:"flex-start" }} >
      <CardContent>
        <Grid container alignItems="center" direction="row">
          <Grid item>
            <CopyToClipboardButton text={props.code}/>
          </Grid>
          <Grid item>
            <Typography color="text.secondary">
              {props.title}
            </Typography>
          </Grid>
        </Grid>
        <SyntaxHighlighter language={"bash"}>    
          {props.code}
        </SyntaxHighlighter>



      </CardContent>
    </Card>
  )
}

export {SnippetWithCopyButton}