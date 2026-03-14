import { Link, useLocation } from "react-router-dom"
function Nav(){
    const location = useLocation()
    const params = new URLSearchParams(location.search).toString()
    return <nav className="d-flex flex-column align-items-center">
        <p>
        {location.pathname==='/register'?'Already have an account? ':"Don't have an account? "}
        <Link to={`${location.pathname === '/register' ? '/login' : '/register'}?${params}`}>{location.pathname === '/register' ? 'Login' : 'Sign up'}</Link>        
      </p>
      {location.pathname !== '/authorize' && location.pathname !== '/forgot_password' &&<p>        Forgot your password?  <Link to={`/forgot_password?${params}`}>Recover it</Link>
</p>
      }
    </nav>
}export default Nav