import PasswordInput from "@components/fields/PasswordInput"
import ActionButton from "@components/buttons/ActionButton"
import TextInput from "@components/fields/TextInput"
import { useEffect, useState } from "react"
import { auth_api } from "@services/interceptors"
import {Alert, Card} from "react-bootstrap"
import Captcha from "@components/captcha/Captcha"
import OtpInput from 'react-otp-input';
import { Link } from "react-router-dom"

function Login() {
    const [password, setPassword] = useState('')
    const [username, setUsername] = useState('')
    const [captchaValue, setRecaptchaValue] = useState(null)
    const [err, setErr] = useState('')
    const [otp, setOtp] = useState('')
    const [needsOtp, setNeedsOtp] = useState(false)
    const urlParams = new URLSearchParams(window.location.search)
    const handleOTP = async()=>{

        try{

            const response = await auth_api.post('/otp', {otp: otp})
            setErr('')
            console.log(response)
            window.location.href = window.location.origin+'/authorize'+ '?'+urlParams.toString()
        }catch(err){
            if(err.error ==='too_many_attempts' || err.error==='expired_otp'){
                setErr(<>{err.error_description} <a className="info" onClick={(e)=>{e.preventDefault(); window.location.reload()}}>sign in again</a></>)
            }else{
                setErr(err.error_description)
            }
            
        }
    }
    const handleLogin = async (e) => {
        try {
            e.preventDefault()
                const response = await auth_api.post(`/login`, {username:username, password:password,captchaValue:captchaValue})
                setErr('')
                console.log(response)
                
                // window.location.href =response.request.responseURL
                if(response === 'otp'){
                    setNeedsOtp(true)
                }else{
                    window.location.href = window.location.origin+'/authorize'+ '?'+urlParams.toString()
                }
            

            
        } catch (error) {
            // setErr(error)
            setErr(error.error_description)
            if (error.error === 'invalid_token'){
                window.location.reload()
            }
            window?.grecaptcha?.reset();
        }
    }
    useEffect(()=>{
        console.log(otp)
        if(otp.length===6) handleOTP()
    },[otp])
    return <>
    <Card.Title>{!needsOtp?<h2>Login</h2>:<h2>OTP</h2>}</Card.Title>
    <Card.Body className="d-flex flex-column">
        {needsOtp&&
        <>
        <label style={{textAlign:'center'}}>Enter your OTP:</label>
        <OtpInput
        inputStyle={'otp-input'}
        containerStyle={'otp-container mb-1'}
        value={otp}
        onChange={setOtp}
        numInputs={6}
        renderSeparator={''}
        renderInput={(props) => <input {...props} />}
        />
        </>
}
        {!needsOtp&&<><TextInput value={username} setValue={setUsername} label="Email:" className="mb-1"/>
        <PasswordInput value={password} setValue={setPassword} label="Password:" className="mb-2"/>
        <Captcha setRecaptchaValue={setRecaptchaValue} className="mb-2"/></>}
        {!needsOtp&&<ActionButton text={"Login"} onClick={handleLogin} disabled={!username ||!password || !captchaValue}/>}
        {err&&<Alert variant="danger" className="mt-1">{err}</Alert>}
    </Card.Body>
    </>
}

export default Login