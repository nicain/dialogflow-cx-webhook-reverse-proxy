import * as React from 'react';
import {useState} from "react";
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
import Home from '@mui/icons-material/Home';
import School from '@mui/icons-material/School';
import Login from '@mui/icons-material/Login';
import Logout from '@mui/icons-material/Logout';
import Stream from '@mui/icons-material/Stream';
import { useEffect } from "react";
import Tooltip from '@mui/material/Tooltip';
import { PageContent } from './PageContent.js';
import { SessionExpiredModal } from './SessionExpiredModal.js';
import { getCookie, LOGIN_COOKIE_NAME } from './Utilities.js';
import {useQueryState} from "./UseQueryState.js"


const drawerWidth = 240;
const TITLE = 'Securing Dialogflow CX with Webhook Fulfillment: VPC Service Controls'

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
      <ListItem key={props.text} disablePadding sx={{ display: 'block' }} selected={props.activePage === props.targetPage}>
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
  props.dataModel.activePage = {current: null, set: null};
  [props.dataModel.activePage.current, props.dataModel.activePage.set] =  useQueryState('page');

  props.dataModel.projectData.project_id = {current: null, set: null};
  [props.dataModel.projectData.project_id.current, props.dataModel.projectData.project_id.set] = useQueryState('project_id')
  props.dataModel.projectData.accessPolicyTitle = {current: null, set: null};
  [props.dataModel.projectData.accessPolicyTitle.current, props.dataModel.projectData.accessPolicyTitle.set] = useQueryState('access_policy_title')

  const queryParams = {};
  if (typeof activePage==='string') {
    queryParams['page'] = props.dataModel.activePage.current
  }
  if (typeof props.dataModel.projectData.project_id.current==='string') {
    queryParams['project_id'] = props.dataModel.projectData.project_id.current
  }
  if (typeof props.dataModel.projectData.accessPolicyTitle.current==='string') {
    queryParams['access_policy_title'] = props.dataModel.projectData.accessPolicyTitle.current
  }
  props.dataModel.queryParams = queryParams
  const queryStr = new URLSearchParams(props.dataModel.queryParams).toString();
  let loginButton = <DrawerButton open={open} text={"Login"} icon={Login} href={`http://${window.location.host}/session?${queryStr}`} dataModel={props.dataModel} targetPage={null} activePage={props.dataModel.activePage.current} onClick={() => {
    props.dataModel.loginRedirect.set(true);
  }}/>
  let logoutButton = <DrawerButton open={open} text={"Logout"} icon={Logout} href={`http://${window.location.host}/logout?${queryStr}`} dataModel={props.dataModel} targetPage={null} activePage={props.dataModel.activePage.current}/>
  let HomeButton = <DrawerButton open={open} text={"Home"} icon={Home} dataModel={props.dataModel} targetPage='home' onClick={() => {props.dataModel.activePage.set('home')}} activePage={props.dataModel.activePage.current}/>
  let TutorialButton = <DrawerButton open={open} text={"Tutorial"} icon={School} dataModel={props.dataModel} targetPage='tutorial' onClick={() => {
    props.dataModel.activePage.set('tutorial'); 
    resetStateOnPageChange(props.dataModel)
  }} activePage={props.dataModel.activePage.current}/>
  let LiveDemoButton = <DrawerButton open={open} text={"Live Demo"} icon={Stream} dataModel={props.dataModel} targetPage='liveDemo' onClick={() => {
    props.dataModel.activePage.set('liveDemo');
    resetStateOnPageChange(props.dataModel)
  }} activePage={props.dataModel.activePage.current}/>

  return (
    <div>
      <SessionExpiredModal dataModel={props.dataModel}/>
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
          </List>
        </Drawer>
        <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
          <DrawerHeader />
          <PageContent
            dataModel={props.dataModel}
            activePage={props.dataModel.activePage.current}
          />
        </Box>
      </Box>
    </div>
  );
}

export {MiniDrawer}