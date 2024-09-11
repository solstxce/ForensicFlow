// auth.js

// Function to handle login
async function login(username, password) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include' // This is important for including cookies
        });

        if (response.ok) {
            // Redirect to dashboard
            window.location.href = '/dashboard';
        } else {
            const error = await response.json();
            alert(error.error);
        }
    } catch (error) {
        console.error('Login error:', error);
    }
}

// Function to handle authenticated API requests
async function apiRequest(url, options = {}) {
    const response = await fetch(url, { 
        ...options, 
        credentials: 'include' // This is important for including cookies
    });

    if (response.status === 401) {
        // Token is invalid or expired
        window.location.href = '/login';
        return;
    }

    return response;
}

// Function to handle logout
function logout() {
    // Clear the cookie by setting it to expire in the past
    document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    window.location.href = '/login';
}

// Check login status on page load
document.addEventListener('DOMContentLoaded', function() {
    const path = window.location.pathname;
    if (path !== '/login' && path !== '/register') {
        // We don't need to check for the token here
        // The server will handle unauthorized requests
    }
});