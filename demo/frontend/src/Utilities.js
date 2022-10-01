
const LOGIN_COOKIE_NAME = 'user_logged_in'

function backendEnabled(dataModel) {

  if (typeof(dataModel.validProjectId.current) != "boolean") {
    return false
  }

  if (
    dataModel.loggedIn.current===true &&
    dataModel.validProjectId.current===true) {
    return true
  } else {
    return false
  }
}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

function deleteCookie(name) {
  if( getCookie( name ) ) {
    document.cookie = `${name}=;domain=${window.location.hostname};expires=Thu, 01 Jan 1970 00:00:01 GMT`;
  }
}

function handleTokenExpired(dataModel) {
  console.log('handleTokenExpired')
  dataModel.sessionExpiredModalOpen.set(true)
  deleteCookie(LOGIN_COOKIE_NAME)
  dataModel.projectData.principal.set(null)
}

export {backendEnabled, handleTokenExpired, getCookie, LOGIN_COOKIE_NAME}