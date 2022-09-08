import Box from '@mui/material/Box';
import { Document, Page } from 'react-pdf';
import diagram_sd from './VPC_SC_diagram_latest.pdf';
import Paper from '@mui/material/Paper';
import {getPage} from './DataModel.js';

function StateImage(props) {
  let renderedPageNumber = props.dataModel.renderedPageNumber
  let allStates = props.dataModel.allStates
  let pageMapper = props.dataModel.pageMapper
  const currPage = getPage(allStates, pageMapper) ? getPage(allStates, pageMapper) : 33
  const isLoading = renderedPageNumber.current !== currPage;
  const pageHeight = 300
  return(
  <Document file={diagram_sd}>
    <Box sx={{ width: "75%"}} display="flex" justifyContent="center" alignItems="center" margin="auto">
      {isLoading && renderedPageNumber.current ? (
        <Page 
            key={renderedPageNumber.current}
            className="prevPage"
            pageNumber={renderedPageNumber.current} 
            height={pageHeight}
            loading={<div><Box sx={{ width: "75%"}} display="flex" justifyContent="center" alignItems="center" margin="auto"><Paper variant="string" sx={{ width: "75%", height:pageHeight}}></Paper></Box></div>}
          />
        ) : null}
        <Page
          key={currPage}
          pageNumber={currPage}
          height={pageHeight}
          onRenderSuccess={() => {renderedPageNumber.set(currPage)}}
          loading={<div><Box sx={{ width: "75%"}} display="flex" justifyContent="center" alignItems="center" margin="auto"><Paper variant="string" sx={{ width: "75%", height:pageHeight}}></Paper></Box></div>}
        />
    </Box>
  </Document>
)}

export {StateImage}