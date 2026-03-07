import { useState } from 'react'
import { Routes, Route } from 'react-router-dom'
import Login from '@routes/login/Login'
import Register from '@routes/register/Register'
import ForgotPassword from '@routes/forgot_password/ForgotPassword'
import ChangePasswordWithRecoverLink from '@routes/change_password_with_recover_link/ChangePasswordWithRecoverLink'
import Nav from '@ui/Nav'
import Authorize from '@routes/authorize/Authorize'
import 'bootstrap/dist/css/bootstrap.min.css';
import '@styles/index.scss'
import { Card } from 'react-bootstrap'
function App() {

  return (
    <>
    <div className='container'>

    <Card>

      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot_password" element={<ForgotPassword />} />
        <Route path="/change_password_with_recover_link" element={<ChangePasswordWithRecoverLink />} />
        <Route path="/authorize" element={<Authorize/>}/>
      </Routes>
    <Nav/>
    </Card>
    </div>
    </>
  )
}

export default App
