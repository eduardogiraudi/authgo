import { useState } from "react"
import PasswordInput from "@components/fields/PasswordInput"
import ActionButton from "@components/buttons/ActionButton"
import TextInput from "@components/fields/TextInput"
import { auth_api } from "@services/interceptors"
import { Alert, Card } from "react-bootstrap"
import { useNavigate } from "react-router-dom"
import Captcha from "@components/captcha/Captcha"

function Register() {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [err, setErr] = useState('')
    const [captchaValue, setRecaptchaValue] = useState(null)
    const navigate = useNavigate()
    const validatePassword = () => {
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!-@#$%^&*(),.?":{}|<>])[A-Za-z\d!-@#$%^&*(),.?":{}|<>]{12,36}$/;
        return passwordRegex.test(password)
    }
    const validateConfirmPassword = () => {
        return password === confirmPassword
    }
    const validateEmail = (email) => {
        return email.match(
          /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        );
      };
    const handleRegistration = async () => {
        try {
            if (password === confirmPassword && validatePassword() && validateEmail(username)) {
                await auth_api.post('/register', JSON.stringify({
                    password: password,
                    username: username,
                    captchaValue: captchaValue
                }))
                navigate('/?'+new URLSearchParams(location.search).toString())
                
            }
        } catch (error) {
            setErr(error.error_description)
            window?.grecaptcha?.reset();
        }
    }
    return (
        <>
        <Card.Title>
            <h2>Register</h2>
        </Card.Title>
        <Card.Body className="d-flex flex-column">


            <TextInput value={username} setValue={setUsername} label="Email:" className=""
            error={!validateEmail(username)&&username&&`${username} is not a valid email.`}

            />
            <PasswordInput 
            className=""
                value={password} 
                setValue={setPassword} 
                label="Password:" 
                error={!validatePassword() && password && 'Password must be between 12 and 36 characters, include an uppercase letter, a lowercase letter, a number, and a symbol.'}
                />
            

            <PasswordInput 
            className="mb-3"
                value={confirmPassword} 
                setValue={setConfirmPassword} 
                label="Confirm password" 
                error={!validateConfirmPassword() && confirmPassword && 'The passwords do not match.'}
                />
            
            <Captcha setRecaptchaValue={setRecaptchaValue} className="mb-2"/>
            <ActionButton 
                text="Register" 
                onClick={handleRegistration} 
                disabled={!(validatePassword()&& password===confirmPassword && captchaValue&&validateEmail(username))}
                />
            {err && <Alert variant="danger">{err}</Alert>}

                </Card.Body>
        </>
    )
}

export default Register
