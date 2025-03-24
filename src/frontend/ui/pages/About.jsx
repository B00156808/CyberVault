import React from 'react';
import { Link } from 'react-router-dom';

const About = ({ goToHome }) => {
  return (
    <div>
      <h2>About Us</h2>
      <p>CyberVault is the ultimate solution for secure data storage.</p>
      
      {/* Link back to Home page */}
      <p>
        For award-winning security analysis, <Link to="/">head to Home</Link>.
      </p>

    </div>
  );
};

export default About;
