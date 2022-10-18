import { Document, Page } from 'react-pdf';
import diagram_sd from './VPC_SC_diagram_latest.pdf';
import Paper from '@mui/material/Paper';
import {getPage} from './DataModel.js';

function ArchitectureImage(props) {
  const isLoading = props.renderedPageNumber.current !== props.currPage;
  return (
    <Paper variant="string" sx={{ width:props.width, height:props.pageHeight}}>
      <Document file={diagram_sd} loading="">
          {
            (isLoading && props.renderedPageNumber.current) ? (
              <Page 
                key={props.renderedPageNumber.current}
                className="prevPage"
                pageNumber={props.renderedPageNumber.current} 
                height={props.pageHeight}
                loading=""
              />
            ) : null
          }
          <Page
            key={props.currPage}
            pageNumber={props.currPage}
            height={props.pageHeight}
            onRenderSuccess={() => {props.renderedPageNumber.set(props.currPage)}}
            loading=""
          />
      </Document>
    </Paper>
  )
}

function StateImage(props) {
  let renderedPageNumber = props.dataModel.renderedPageNumber
  let allStates = props.dataModel.allStates
  let pageMapper = props.dataModel.pageMapper
  const currPage = getPage(allStates, pageMapper).page ? getPage(allStates, pageMapper).page : 33
  
  
  return ArchitectureImage({renderedPageNumber:renderedPageNumber, currPage:currPage, pageHeight:300, width:750})
}

export {StateImage, ArchitectureImage}