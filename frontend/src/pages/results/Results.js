import React, { useState } from 'react';

const Results = () => {
  const [status, setStatus] = useState(''); // Set initial status as needed
  const [data, setData] = useState({});
  const [errorMessage, setErrorMessage] = useState('');
  const [email, setEmail] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch('http://localhost:5000/send_emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email
        }),
      });

      if (response.ok) {
        const result = await response.json();
        setStatus('success');
        setData(result.Data.responses); // Assuming your response structure is like this
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

  return (
    <div>
      {status === 'success' ? (
        <div>
          <h1>Best Fit Candidates</h1>
          <h2>{data}</h2>
          <table border="1">
            <thead>
              <tr>
                <th>Candidate ID</th>
                <th>Email</th>
                <th>Fit Score</th>
              </tr>
            </thead>
            <tbody>
              {data['best_fit_candidates'].map((candidate) => (
                <tr key={candidate['candidate_id']}>
                  <td>{candidate['candidate_id']}</td>
                  <td>{candidate['email']}</td>
                  <td>{candidate['fit_score']}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <form onSubmit={handleSubmit}>
            {data['best_fit_candidates'].map((candidate) => (
              <input
                key={candidate['candidate_id']}
                type="hidden"
                name="emails"
                value={candidate['email']}
              />
            ))}
            <input
              type="hidden"
              name="job_role"
              value={data.job_role}
            />
            <input
              type="email"
              placeholder="Enter Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
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
