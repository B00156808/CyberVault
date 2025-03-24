// src/pages/Home.jsx
import React from 'react';
import { Link } from 'react-router-dom';

const Home = () => {
  return (
    <div>
      <h1>Welcome to CyberVault</h1>
      <p>
  Welcome to <strong>CyberVault</strong>, your ultimate digital fortress for secure data storage and management. At CyberVault, we combine cutting-edge technology with robust security measures to ensure that your most valuable information is protected from unauthorized access. With a user-friendly interface and powerful encryption algorithms, we are committed to offering the highest level of protection for personal and business data alike. Whether you're looking to safeguard sensitive documents or store important files, CyberVault stands as the best choice for those who prioritize security, reliability, and peace of mind. Trust us to keep your data safe—because when it comes to security, we don’t take any chances.
</p>
      
      {/* Link to About Page */}
      <Link to="/about">Learn more about us</Link>
    </div>
  );
};

export default Home;
