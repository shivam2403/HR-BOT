import React, { useState, useContext } from 'react';
import './home.css'; // Update the path
import { useUser } from '../../context/UserContext';
import { useNavigate } from 'react-router-dom';


const Home = () => {
  const [questionId, setQuestionId] = useState(1);
  const [jobRole, setJobRole] = useState('');
  const { user, loginUser, logoutUser } = useUser();
  const navigate=useNavigate();

  const fetchQuestion = () => {
    fetch(`http://localhost:5000/get_question/${user.applied_job_role}?question_id=${questionId}`)
      .then(response => response.json())
      .then(data => {
        const questionElement = document.getElementById('question');
        if (data.question) {
          questionElement.innerText = data.question;
          setQuestionId(prevId => prevId + 1);
        } else {
          questionElement.innerText = 'No more questions available';
          document.getElementById('nextQuestion').disabled = true;
        }
      })
      .catch(error => console.error('Error:', error));
  };

  const handleNextQuestion = () => {
    const response = document.getElementById('response').value;
    const candidateName = document.getElementById('candidateName').innerText;

    const payload = {
      candidate_name: candidateName,
      question_id: questionId - 1,
      response: response,
    };

    fetch('http://localhost:5000/submit_response', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    })
      .then(response => response.json())
      .then(data => {
        // Handle response data if needed
      })
      .catch(error => {
        console.error('Error:', error);
      });

    fetchQuestion();
  };

  const handleStartInterview = () => {
    setQuestionId(1);
    const candidateName = document.getElementById('candidateName').innerText;
    setJobRole(document.getElementById('appliedJobRole').innerText);
    fetchQuestion();
  };

  const handleStartSpeech = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new SpeechRecognition();
    recognition.lang = 'en-US';

    let isListening = false;

    if (!isListening) {
      recognition.start();
      isListening = true;
      document.getElementById('startSpeech').innerText = 'Stop Speaking';
    } else {
      recognition.stop();
      isListening = false;
      document.getElementById('startSpeech').innerText = 'Start Speaking';
    }

    recognition.onresult = function (event) {
      const transcript = event.results[0][0].transcript;
      const responseTextarea = document.getElementById('response');
      responseTextarea.value += transcript;
    };

    recognition.onerror = function (event) {
      console.error('Speech recognition error:', event.error);
      isListening = false;
      document.getElementById('startSpeech').innerText = 'Start Speaking';
    };

    recognition.onend = function () {
      isListening = false;
      document.getElementById('startSpeech').innerText = 'Start Speaking';
    };
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

      <div className="home">
        {user ? (
          <React.Fragment>
            <div className="d_title">
              <h1>
                Candidate <span className="interview_text">Interview</span>
              </h1>
            </div>

            <div className="user_info">
              <label className="user_info_input" htmlFor="candidateName">
                Your Name: <span id="candidateName">{user.name}</span>
              </label>
              <p className="user_info_input">
                Applied Job Role: <span id="appliedJobRole">{user.applied_job_role}</span>
              </p>
            </div>

            <button className="role_input_btn" onClick={handleStartInterview}>
              Start Interview
            </button>

            <div className="q_down">
              <h2 className="showcase_title">Question Showcase</h2>
              <div className="q_container" id="questionContainer">
                <p className="q_text" id="question"></p>
                <textarea className="response_textarea" id="response" placeholder="Your response..."></textarea>
                <button className="role_input_btn" id="nextQuestion" onClick={handleNextQuestion}>
                  Next Question
                </button>
              </div>
            </div>

            <button className="role_input_btn" id="startSpeech" onClick={handleStartSpeech}>
              Start Speaking
            </button>
          </React.Fragment>
        ) : (
          <p>
            Please <a href="http://localhost:3000/login">log in</a> to access this page.
          </p>
        )}
      </div>
    </>
  );
};

export default Home;
