import axios from "axios";

import { GoogleLogin, GoogleLogout } from 'react-google-login';

const onFailure = (err) => {
  console.log('failed', err);
};

function googleLogin(clientId, setProfile){
  
  const onSuccess = (res) => {
    axios.defaults.headers.get['Authorization'] = "Bearer " + res.tokenId; 
    axios.defaults.headers.post['Authorization'] = "Bearer " + res.tokenId; 
    setProfile(res.profileObj);
    console.log('success');
  };

  return (<GoogleLogin
        clientId={clientId}
        buttonText="Sign in with Google"
        onSuccess={onSuccess}
        onFailure={onFailure}
        cookiePolicy={'single_host_origin'}
        isSignedIn={true}
    />)
}

function googleLogout(clientId, profile, setProfile){

  const logOut = () => {
    setProfile(null);
  };

  return (
    <div>
      <GoogleLogout clientId={clientId} buttonText="Log out" onLogoutSuccess={logOut} />
      <h3>User Logged in</h3>
      <p>Name: {profile.name}</p>
      <p>Email Address: {profile.email}</p>
    </div>)
}

export {googleLogin, googleLogout}