import * as React from 'react';
import { styled, useTheme } from '@mui/material/styles';
import Box from '@mui/material/Box';
import MuiDrawer from '@mui/material/Drawer';
import MuiAppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import List from '@mui/material/List';
import CssBaseline from '@mui/material/CssBaseline';
import Typography from '@mui/material/Typography';
import Divider from '@mui/material/Divider';
import IconButton from '@mui/material/IconButton';
import MenuIcon from '@mui/icons-material/Menu';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import InboxIcon from '@mui/icons-material/MoveToInbox';
import MailIcon from '@mui/icons-material/Mail';
import Settings from '@mui/icons-material/Settings';
import Home from '@mui/icons-material/Home';
import Publish from '@mui/icons-material/Publish';
import School from '@mui/icons-material/School';
import Login from '@mui/icons-material/Login';
import Logout from '@mui/icons-material/Logout';
import Slideshow from '@mui/icons-material/Slideshow';
import Stream from '@mui/icons-material/Stream';
import {useEffect} from "react";
import {StateChangeButtonGrid} from './StateButtonGrid.js'
import {StateImage} from './StateSlides.js'
import {QueryInfo} from './Info.js'
import {AssetStatusPanel} from './AssetStatusPanel.js'
import Tooltip from '@mui/material/Tooltip';

const drawerWidth = 240;
const TITLE = 'VPC-SC Live Demo'
const LOGIN_COOKIE_NAME = 'user_logged_in'

const openedMixin = (theme) => ({
  width: drawerWidth,
  transition: theme.transitions.create('width', {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.enteringScreen,
  }),
  overflowX: 'hidden',
});

const closedMixin = (theme) => ({
  transition: theme.transitions.create('width', {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  overflowX: 'hidden',
  width: `calc(${theme.spacing(7)} + 1px)`,
  [theme.breakpoints.up('sm')]: {
    width: `calc(${theme.spacing(8)} + 1px)`,
  },
});

const DrawerHeader = styled('div')(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'flex-end',
  padding: theme.spacing(0, 1),
  // necessary for content to be below app bar
  ...theme.mixins.toolbar,
}));

const AppBar = styled(MuiAppBar, {
  shouldForwardProp: (prop) => prop !== 'open',
})(({ theme, open }) => ({
  zIndex: theme.zIndex.drawer + 1,
  transition: theme.transitions.create(['width', 'margin'], {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  ...(open && {
    marginLeft: drawerWidth,
    width: `calc(100% - ${drawerWidth}px)`,
    transition: theme.transitions.create(['width', 'margin'], {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  }),
}));

const Drawer = styled(MuiDrawer, { shouldForwardProp: (prop) => prop !== 'open' })(
  ({ theme, open }) => ({
    width: drawerWidth,
    flexShrink: 0,
    whiteSpace: 'nowrap',
    boxSizing: 'border-box',
    ...(open && {
      ...openedMixin(theme),
      '& .MuiDrawer-paper': openedMixin(theme),
    }),
    ...(!open && {
      ...closedMixin(theme),
      '& .MuiDrawer-paper': closedMixin(theme),
    }),
  }),
);

function DrawerButton(props) {
  
  const Icon = props.icon
  return (
    <Tooltip title={props.open ? "" : props.text} disableInteractive arrow placement="top">
      <ListItem key={props.text} disablePadding sx={{ display: 'block' }} selected={props.dataModel.activePage.current === props.pageNumber}>
        <ListItemButton
          sx={{
            minHeight: 48,
            justifyContent: props.open ? 'initial' : 'center',
            px: 2.5,
          }}
          href={props.href}
          onClick={props.onClick}
        >
          <ListItemIcon
            sx={{
              minWidth: 0,
              mr: props.open ? 3 : 'auto',
              justifyContent: 'center',
            }}
          >
          <Icon />
          </ListItemIcon>
          <ListItemText primary={props.text} sx={{ opacity: props.open ? 1 : 0 }} />
        </ListItemButton>
      </ListItem>
    </Tooltip>
)}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

function MiniDrawer(props) {

  const theme = useTheme();
  const [open, setOpen] = React.useState(false);

  const handleDrawerOpen = () => {
    setOpen(true);
  };

  const handleDrawerClose = () => {
    setOpen(false);
  };

  useEffect(() => {
    const is_logged_in = getCookie(LOGIN_COOKIE_NAME) === 'true';
    props.dataModel.loggedIn.set(is_logged_in)
  });

  function resetStateOnPageChange(dataModel) {
    for (const [key, state] of Object.entries(dataModel.allStates)) {
      state.status.set(false)
      state.isUpdating.set(false)
      state.blocked.set(false)
    }
  }

  let loginButton = <DrawerButton open={open} text={"Login"} icon={Login} href={`http://${window.location.host}/session`} dataModel={props.dataModel} pageNumber={null}/>
  let logoutButton = <DrawerButton open={open} text={"Logout"} icon={Logout} href={`http://${window.location.host}/logout`} dataModel={props.dataModel} pageNumber={null}/>
    
  let HomeButton = <DrawerButton open={open} text={"Home"} icon={Home} dataModel={props.dataModel} pageNumber={0} onClick={() => {props.dataModel.activePage.set(0)}}/>
  let TutorialButton = <DrawerButton open={open} text={"Tutorial"} icon={School} dataModel={props.dataModel} pageNumber={1} onClick={() => {
    props.dataModel.activePage.set(1); 
    resetStateOnPageChange(props.dataModel)
  }}/>
  let DeployInstructionsButton = <DrawerButton open={open} text={"Launch Demo"} icon={Settings} dataModel={props.dataModel} pageNumber={2} onClick={() => {props.dataModel.activePage.set(2)}}/>
  let LiveDemoButton = <DrawerButton open={open} text={"Live Demo"} icon={Stream} dataModel={props.dataModel} pageNumber={3} onClick={() => {
    props.dataModel.activePage.set(3);
    resetStateOnPageChange(props.dataModel)
  }}/>
  
  var StateChangeButtonGridCurr
  var StateImageCurr
  var AssetStatusPanelCurr
  if (props.dataModel.activePage.current === 1) {
    StateImageCurr = <StateImage dataModel={props.dataModel}/>
    StateChangeButtonGridCurr = <StateChangeButtonGrid dataModel={props.dataModel} liveMode={false}/>
  } else if (props.dataModel.activePage.current === 2) {
    AssetStatusPanelCurr = <AssetStatusPanel dataModel={props.dataModel}/>
  } else if (props.dataModel.activePage.current === 3) {
    StateImageCurr = <StateImage dataModel={props.dataModel}/>
    StateChangeButtonGridCurr = <StateChangeButtonGrid dataModel={props.dataModel} liveMode={true}/>
  } 

  return (
    <div>
      <Box sx={{ display: 'flex' }}>
        <CssBaseline />
        <AppBar position="fixed" open={open}>
          <Toolbar>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              onClick={handleDrawerOpen}
              edge="start"
              sx={{
                marginRight: 5,
                ...(open && { display: 'none' }),
              }}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" noWrap component="div">
              {TITLE}
            </Typography>
          </Toolbar>
        </AppBar>
        <Drawer variant="permanent" open={open}>
          <DrawerHeader>
            <IconButton onClick={handleDrawerClose}>
              {theme.direction === 'rtl' ? <ChevronRightIcon /> : <ChevronLeftIcon />}
            </IconButton>
          </DrawerHeader>
          <Divider />
          <List>
            {HomeButton}
            {loginButton}
            {props.dataModel.loggedIn.current ? logoutButton : <></>}
          </List>
          <Divider />
          <List>
            {TutorialButton}
            {LiveDemoButton}
            {DeployInstructionsButton}
          </List>
        </Drawer>
        <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
          <DrawerHeader />
          <Typography paragraph>
            Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
            tempor incididunt ut labore et dolore magna aliqua. Rhoncus dolor purus non
            enim praesent elementum facilisis leo vel. Risus at ultrices mi tempus
            imperdiet. Semper risus in hendrerit gravida rutrum quisque non tellus.
            Convallis convallis tellus id interdum velit laoreet id donec ultrices.
            Odio morbi quis commodo odio aenean sed adipiscing. Amet nisl suscipit
            adipiscing bibendum est ultricies integer quis. Cursus euismod quis viverra
            nibh cras. Metus vulputate eu scelerisque felis imperdiet proin fermentum
            leo. Mauris commodo quis imperdiet massa tincidunt. Cras tincidunt lobortis
            feugiat vivamus at augue. At augue eget arcu dictum varius duis at
            consectetur lorem. Velit sed ullamcorper morbi tincidunt. Lorem donec massa
            sapien faucibus et molestie ac.
          </Typography>
          {StateImageCurr}
          {StateChangeButtonGridCurr}
          {AssetStatusPanelCurr}
        </Box>
      </Box>
    </div>
  );
}

export {MiniDrawer}