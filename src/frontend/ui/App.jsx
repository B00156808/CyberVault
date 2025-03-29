import React, { useState } from "react";
import { HashRouter as Router, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import About from "./pages/About";

// Import custom styles (CSS)
import './index.css';  // Import your own CSS file here

function App() {
  const [count, setCount] = useState(0);

  return (
    <Router>
      <div>
        <a href="https://react.dev" target="_blank" rel="noopener noreferrer">
          <img src="/react-logo.svg" className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>CyberVault</h1>
      <div className="card">
        <button onClick={() => setCount(count + 1)}>
          count is {count}
        </button>
      </div>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
      </Routes>
    </Router>
  );
}

export default App;
