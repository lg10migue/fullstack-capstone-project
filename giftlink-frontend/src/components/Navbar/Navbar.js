import React from "react";

export default function Navbar() {
    return (
        <nav className="navbar navbar-expand-lg navbar-light bg-light">
            <a className="navbar-brand" href="/">
                GiftLink
            </a>
            <div className="collapse navbar-collapse" id="navbarNav">
                <ul className="navbar-nav">
                    {/* Task 1: Add links to Home and Gifts below*/}
                    <li className="nav-item">
                        <a href="/home.html" className="nav-link">
                            Home
                        </a>
                    </li>
                    <li className="nav-item">
                        <a href="/app" className="nav-link">
                            Gifts
                        </a>
                    </li>
                </ul>
            </div>
        </nav>
    );
}
