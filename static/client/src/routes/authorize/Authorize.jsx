import { useEffect, useState } from "react"
import { auth_api } from "@services/interceptors"
import ActionButton from "@components/buttons/ActionButton"
import { useLocation } from "react-router-dom"
import { Alert, Card } from "react-bootstrap"

function Authorize(){
    const [scopes, setScopes] = useState([])
    const location = useLocation()
    const [err, setErr] = useState('')
    const handleAuthorize =async (e)=>{
        try{

            let code = await auth_api.post('/authorize',JSON.stringify({'confirmation':true}))
            window.location.href=new URLSearchParams(location.search).get('redirect_uri')+ '?'+'state='+ new URLSearchParams(location.search).get('state') + '&code='+code.code
        }catch(error){
            if (error.error === 'invalid_token'){
                window.location.reload()
            }
            setErr(error.error_description)
        }
    }  
    useEffect(()=>{
        
        (async()=>{
            let details = await auth_api.get('/scope_details')
            setScopes(details)
        })()
    },[])
    return <><Card.Title>
        <h2>Authorize</h2>
    </Card.Title>
    <Card.Body className="d-flex flex-column">
    <p>By clicking 'Authorize' button, you give consent for the application to access the following data:</p>
    <ul>
        {scopes.map((item, index)=>{
            return <li key={index}>
                {item}
            </li>
        })}
    </ul>


 <ActionButton text="Authorize" onClick={handleAuthorize}/>
 {err&&<Alert variant="danger">{err}</Alert>}
    </Card.Body></>
}export default Authorize