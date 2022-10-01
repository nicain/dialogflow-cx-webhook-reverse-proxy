import React from "react";
import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";
import './styles.css';
import {MiniDrawer} from './Drawer'
import {DataModel} from "./DataModel.js";


export default function App() {
  const dataModel = DataModel();
  return (
    <BrowserRouter>
      <Routes>
          <Route path="/" element={<MiniDrawer dataModel={dataModel}/>} />
       </Routes>
    </BrowserRouter>
  );
}
