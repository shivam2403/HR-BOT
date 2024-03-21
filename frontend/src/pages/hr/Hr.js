import React, { useState } from 'react';
import './hr.css';
import { useUser } from '../../context/UserContext';
import { Navigate, redirect, useNavigate } from 'react-router-dom';

const HR = () => {
  const [jobRole, setJobRole] = useState('');
  const [jobDescription, setJobDescription] = useState('');
  const [keySkills, setKeySkills] = useState('');
  const [requiredExperience, setRequiredExperience] = useState('');
  const {logoutUser}=useUser();
  const navigate=useNavigate();


  const handleFormSubmit = async (e) => {
    e.preventDefault();

    const formData = {
      jobRole,
      jobDescription,
      keySkills,
      requiredExperience,
    };

    try {
      const response = await fetch('http://localhost:5000/save_hr_input_and_generate_questions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        const data = await response.json();
        console.log('Success:', data);
      } else {
        const errorData = await response.json();
        console.error('Error:', errorData.message);
      }
    } catch (error) {
      console.error('An error occurred:', error);
    }
  };

  const handleLogout=()=>{
    logoutUser();
    navigate('/login')
  }

  return (
<>
        <div className="nav">
        <h1 className="nav_title"><a className="nav_title_prefix" href="/">Funnel<span className="title_text">HQ</span></a></h1>
        <div className="nav_right">
        <button className='btn' onClick={handleLogout}>Logout</button>
        </div>
      </div>
    <div className="hr">
      <h1 className="hr_title">HR Input Form</h1>
      <form className="hr_form" onSubmit={handleFormSubmit}>
        <div className="hr_email">
          <div className="hr_label">
            <label htmlFor="jobRole">Job Role:</label>
          </div>
          <div className="hr_input_container">
            <input
              className="hr_input"
              type="text"
              id="jobRole"
              name="jobRole"
              value={jobRole}
              onChange={(e) => setJobRole(e.target.value)}
              />
          </div>
        </div>

        <div className="hr_email">
          <div className="hr_label">
            <label htmlFor="jobDescription">Job Description:</label>
          </div>
          <div className="hr_input_container">
            <textarea
              className="hr_textarea"
              id="jobDescription"
              name="jobDescription"
              value={jobDescription}
              onChange={(e) => setJobDescription(e.target.value)}
              ></textarea>
          </div>
        </div>

        <div className="hr_email">
          <div className="hr_label">
            <label htmlFor="keySkills">Key Skills:</label>
          </div>
          <div className="hr_input_container">
            <input
              className="hr_input"
              type="text"
              id="keySkills"
              name="keySkills"
              value={keySkills}
              onChange={(e) => setKeySkills(e.target.value)}
              />
          </div>
        </div>

        <div className="hr_email">
          <div className="hr_label">
            <label htmlFor="requiredExperience">Required Experience:</label>
          </div>
          <div className="hr_input_container">
            <input
              className="hr_input"
              type="text"
              id="requiredExperience"
              name="requiredExperience"
              value={requiredExperience}
              onChange={(e) => setRequiredExperience(e.target.value)}
              />
          </div>
        </div>

        <button className="btn" type="submit">
          Submit
        </button>
      </form>
    </div>
              </>
  );
};

export default HR;
