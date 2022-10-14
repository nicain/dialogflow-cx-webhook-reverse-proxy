import { Document, Page } from 'react-pdf';
import diagram_sd from './VPC_SC_diagram_latest.pdf';
import Paper from '@mui/material/Paper';
import {getPage} from './DataModel.js';

function StateImage(props) {
  let renderedPageNumber = props.dataModel.renderedPageNumber
  let allStates = props.dataModel.allStates
  let pageMapper = props.dataModel.pageMapper
  const currPage = getPage(allStates, pageMapper).page ? getPage(allStates, pageMapper).page : 33
  const isLoading = renderedPageNumber.current !== currPage;
  const pageHeight = 300
  return(

  <Paper variant="string" sx={{ width:750, height:pageHeight, pl:2}}>
    <Document file={diagram_sd} loading="">
        {
          (isLoading && renderedPageNumber.current) ? (
            <Page 
              key={renderedPageNumber.current}
              className="prevPage"
              pageNumber={renderedPageNumber.current} 
              height={pageHeight}
              loading=""
            />
          ) : null
        }
        <Page
          key={currPage}
          pageNumber={currPage}
          height={pageHeight}
          onRenderSuccess={() => {renderedPageNumber.set(currPage)}}
          loading=""
        />
    </Document>
  </Paper>
  )
}

export {StateImage}