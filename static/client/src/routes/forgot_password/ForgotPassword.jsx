import { Card } from "react-bootstrap"
import { useState } from "react"
import TextInput from "@components/fields/TextInput"
import Captcha from "@components/captcha/Captcha"
import ActionButton from "@components/buttons/ActionButton"
import { auth_api } from "@services/interceptors"
import { Alert } from "react-bootstrap"
import OtpInput from 'react-otp-input';
import { Link } from "react-router-dom"
import PasswordInput from "@components/fields/PasswordInput"


function ForgotPassword() {
  const [email, setEmail] = useState("")  
  const [captchaValue, setRecaptchaValue] = useState(null)
  const [err, setErr]  = useState("")
  const [id, setId] = useState("")
  const [otp, setOtp] = useState("")
  const [success, setSuccess] = useState(false)
  const [password, setPassword] = useState('')
  const params = new URLSearchParams(location.search).toString()
  const validatePassword = () => {
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!-@#$%^&*(),.?":{}|<>])[A-Za-z\d!-@#$%^&*(),.?":{}|<>]{12,36}$/;
      return passwordRegex.test(password)
  }
  const handleOTP = async () => {
    try {
      const response = await auth_api.post('/change_password_with_otp', { email: email, captchaValue: captchaValue, id:id, otp:otp, newPassword:password })
      setErr('')
      setSuccess(true)
    } catch (err) {
      if(err.error ==='too_many_attempts' || err.error==='expired_otp'){
          setErr(<>{err.error_description} <a className="info" onClick={(e)=>{e.preventDefault(); window.location.reload()}}>sign in again</a></>)
      }else{
          setErr(err.error_description)
      }
    }
  }
  const handleRecovery = async()=>{

      try{
          const response = await auth_api.post('/forgot_password', {email: email, captchaValue:captchaValue})
          setErr('')
          
          setId(response)
      }catch(err){
          
              setErr(err.error_description)
          
          
      }
  }
    return <>
    <Card.Title>

    <h2>Forgot Password</h2>
    </Card.Title>
    <Card.Body>
      {!id &&!success? <>



<TextInput value={email} setValue={setEmail} label="Email:" className="mb-1"/>


      <Captcha setRecaptchaValue={setRecaptchaValue} className="mb-2"/>

      {err&&<Alert variant="danger" className="mt-1">{err}</Alert>}

<div className="d-flex justify-content-center col-md-12"><ActionButton text={"Reset my password"} onClick={handleRecovery} disabled={!email || !captchaValue} /></div>
        </> :!success? <>
          <PasswordInput value={password} setValue={setPassword} label="New password:" className="mb-2" error={!validatePassword() && password && 'Password must be between 12 and 36 characters, include an uppercase letter, a lowercase letter, a number, and a symbol.'}/>

          <OtpInput
                  inputStyle={'otp-input'}
                  containerStyle={'otp-container mb-1'}
                  value={otp}
                  onChange={setOtp}
                  numInputs={8}
                  renderSeparator={''}
                  renderInput={(props) => <input {...props} />}
            />
            <Captcha setRecaptchaValue={setRecaptchaValue} className="mb-2"/>
            <div className="d-flex justify-content-center col-md-12"><ActionButton text={"Submit"} onClick={handleOTP} disabled={otp.length < 8 || !captchaValue || !validatePassword()} /></div>
            {err && <Alert variant="danger" className="mt-1">{err}</Alert>}
          </> : <>
              <Alert variant="success" className="mt-1">Password changed successfully.</Alert>
              <Link to={"/login?"+params}>Sign In</Link>
        </>}
        
      </Card.Body>
    </>
}

export default ForgotPassword   