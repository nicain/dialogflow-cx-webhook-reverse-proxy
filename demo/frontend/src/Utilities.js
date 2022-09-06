
function Capitalize(s)
{
    return s[0].toUpperCase() + s.slice(1);
}

function Sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

export {Capitalize, Sleep}