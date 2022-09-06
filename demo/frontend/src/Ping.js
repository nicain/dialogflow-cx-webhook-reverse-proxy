import axios from "axios";
import {useQuery} from "react-query";

export default function Ping() {
  const {refetch, data, isSuccess} = useQuery('key', 
  () =>
  axios
    .get("/ping")
    .then((res) => res.data),
  {enabled:false, retry:0})
  const handleClick = (event) => {
    refetch();
    event.stopPropagation();
    if (isSuccess){
      console.log(data);
    };
  };


  return (
    <button id="PingButton" onClick={handleClick}>
      Ping!
    </button>
  )
}