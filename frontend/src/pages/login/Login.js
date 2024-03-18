import { useState } from 'react';
import { useUser } from '../../context/UserContext';
import './login.css'
import { Link } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import 'boxicons'



const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const {loginUser}=useUser();
    const navigate=useNavigate();

    const handleLogin = async () => {
        try {
          const response = await fetch('http://localhost:5000/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
          });
    
          console.log('i')
          if (response.ok) {
            const data = await response.json();
            loginUser(data.user);
            navigate('/')
          } else {
            const errorData = await response.json();
            console.error(errorData.message);
          }
        } catch (error) {
          console.error('An error occurred:', error);
        }
      };

  return (
    <div className="login">
      <div className="l_right">
        <div className="l_right_hr"></div>
      </div>
      <div className="l_left">
        <div className="l_left_title">
          <h2 className="l_left_title_heading">Welcome back</h2>
          <p className="l_left_title_desc">Enter your email and password to access your account</p>
        </div>
        <div className="l_form">
          <div className="l_email">
            <label htmlFor="email" className="form-label">Email</label>
            <input type="email" className="form-control l_input" name="email" id="email" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="l_password">
            <label htmlFor="password" className="form-label">Password</label>
            <input
              type="password"
              className="form-control l_input"
              name="password"
              id="password"
              placeholder="Enter your password"
              value={password} 
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="l_reminder">
            <span className="l_reminder_left"><input type="checkbox" name="" id="" /> Remember me</span>
            <Link className="l_reminder_right" to="">Forgot Password?</Link>
          </div>
          <button onClick={handleLogin} className="l_btn">Login</button>
        </div>
        <div className="l_down">
          <div>
            Don't have an account? <Link className="l_down_signup" to="http://localhost:3000/register">Signup</Link>
          </div>
          <div className="l_down_options">
            <div className='icon'>
                <box-icon  type='logo' name='google'></box-icon>
            </div>
            <div className="icon">
                <box-icon name='globe'></box-icon>
            </div>
            <div className="icon">
                <box-icon name='code-alt'></box-icon>
            </div>
            <div className="icon">
                <box-icon type='logo' name='linkedin'></box-icon>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
