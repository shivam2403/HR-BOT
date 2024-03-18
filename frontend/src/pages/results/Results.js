import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';

const Results = () => {
  const [status, setStatus] = useState('');
  const [data, setData] = useState({});
  const [errorMessage, setErrorMessage] = useState('');
  const [email, setEmail] = useState('');
  const { job_role } = useParams();

  useEffect(() => {
    // Fetch data from /get_best_fit_candidates/<job_role> route
    const fetchBestFitCandidates = async () => {
      try {
        const jobRole = job_role; // Replace with the actual job role
        const response = await fetch(`http://localhost:5000/get_best_fit_candidates/${jobRole}`);
        
        if (response.ok) {
          const result = await response.json();
          setStatus('success');
          setData(result.Data);
        } else {
          const errorData = await response.json();
          setStatus('error');
          setErrorMessage(errorData.Data.error_message);
        }
      } catch (error) {
        setStatus('error');
        setErrorMessage('An error occurred while fetching data');
      }
    };

    // Call the function to fetch data from /get_best_fit_candidates/<job_role>
    fetchBestFitCandidates();
  }, [job_role]); // The empty dependency array ensures this useEffect runs only once on component mount

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      // console.log('start')
      const response = await fetch('http://localhost:5000/send_emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email,
        }),
      });

      // console.log('end')
      if (response.ok) {
        const result = await response.json();
        setStatus('success');
        setData(result.Data.responses);
      } else {
        const errorData = await response.json();
        setStatus('error');
        setErrorMessage(errorData.Data.error_message);
      }
    } catch (error) {
      setStatus('error');
      setErrorMessage('An error occurred while fetching data'+error);
    }
  };

  return (
    <div>
      {status === 'success' ? (
        <div>
          <h1>Best Fit Candidates</h1>
          <h2>{data.job_role}</h2>
          <table border="1">
            <thead>
              <tr>
                <th>Candidate ID</th>
                <th>Email</th>
                <th>Fit Score</th>
              </tr>
            </thead>
            <tbody>
              {data.best_fit_candidates.map((candidate) => (
                <tr key={candidate.candidate_id}>
                  <td>{candidate.candidate_id}</td>
                  <td>{candidate.email}</td>
                  <td>{candidate.fit_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <form onSubmit={handleSubmit}>
            {data.best_fit_candidates.map((candidate) => (
              <input
                key={candidate.candidate_id}
                type="hidden"
                name="emails"
                value={candidate.email}
                onChange={(e) => setEmail(e.target.value)}
              />
            ))}
            <input
              type="hidden"
              name="job_role"
              value={data.job_role}
            />
            {/* <input
              type="email"
              placeholder="Enter Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            /> */}
            <input type="submit" value="Send Emails" />
          </form>
        </div>
      ) : (
        <p style={{ color: 'red' }}>An error occurred: {errorMessage}</p>
      )}
    </div>
  );
};

export default Results;
