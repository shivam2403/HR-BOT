import React, { useState } from 'react';
import './register.css';
import { Link, useNavigate } from 'react-router-dom';

const Register = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('candidate');
  const [appliedJobRole, setAppliedJobRole] = useState('');
  const [showAppliedJobRoleField, setShowAppliedJobRoleField] = useState(true);
  const navigate=useNavigate();

  const toggleJobRoleField = () => {
    setShowAppliedJobRoleField((prev) => !prev);
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          name,
          role,
          applied_job_role: showAppliedJobRoleField ? appliedJobRole : undefined,
        }),
      });

      if (response.ok) {
        console.log('Registration successful');
        navigate('/login')
      } else {
        const errorData = await response.json();
        console.error(errorData.message);
      }
    } catch (error) {
      console.error('An error occurred:', error);
    }
  };

  const handleRole=(e)=>{
    setRole(e.target.value);
    toggleJobRoleField();
  }

  return (
    <div className="signup">
      <div className="s_right">
        <div className="s_right_hr"></div>
      </div>
      <div className="s_left">
        <div className="s_left_title">
          <h2 className="s_left_title_heading">Sign Up</h2>
          <p className="s_left_title_desc">Fill the details to create your account</p>
        </div>
        <form onSubmit={handleRegister} className="s_form">
          <div className="s_email">
            <label className="s_email_label" htmlFor="email">
              Email:
            </label>
            <input
              className="s_input"
              type="email"
              name="email"
              placeholder='Enter you email'
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="s_password">
            <label className="s_email_label" htmlFor="password">
              Password:
            </label>
            <input
              className="s_input"
              type="password"
              name="password"
              placeholder='Enter you password'
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="s_email">
            <label className="s_email_label" htmlFor="name">
              Name:
            </label>
            <input
              className="s_input"
              type="text"
              name="name"
              placeholder='Enter you name'
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="s_email">
            <label className="s_email_label" htmlFor="role">
              Select Role:
            </label>
            <select
              className="s_input s_select"
              name="role"
              id="role"
              onChange={handleRole}
            >
              <option value="candidate">Candidate</option>
              <option value="hr">HR</option>
            </select>
            {role}
          </div>
          {showAppliedJobRoleField && (
            <div className="s_email">
              <label className="s_email_label" htmlFor="applied_job_role">
                Applied Job Role:
              </label>
              <input
                className="s_input"
                type="text"
                name="applied_job_role"
                placeholder='Enter you applied role'
                required={showAppliedJobRoleField}
                value={appliedJobRole}
                onChange={(e) => setAppliedJobRole(e.target.value)}
              />
            </div>
          )}
          <div className="s_reminder">
            <span className="l_reminder_left">
              <input type="checkbox" name="" id="" /> Remember me
            </span>
            <Link className="l_reminder_right" to="">
              Forgot Password?
            </Link>
          </div>
          <button type='submit' className="s_btn">
            Get Started
          </button>
        </form>
        <div>
          <span>Already have an account? </span>
          <Link className="s_down_login" to="http://localhost:3000/login">
            LogIn
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Register;
