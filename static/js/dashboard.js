// dashboard.js

document.addEventListener('DOMContentLoaded', function() {
    fetchDashboardData();
});
document.addEventListener('DOMContentLoaded', function() {
    // The user info is now rendered server-side, so we don't need to fetch it here
    // We can add any additional dashboard functionality here if needed
});

async function fetchDashboardData() {
    try {
        const response = await apiRequest('/dashboard');
        if (response.ok) {
            const data = await response.json();
            displayUserInfo(data);
        } else {
            const error = await response.json();
            console.error('Error fetching dashboard data:', error);
            // If unauthorized, redirect to login
            if (response.status === 401) {
                window.location.href = '/login';
            }
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

function displayUserInfo(userInfo) {
    const usernameElement = document.getElementById('username');
    const userRoleElement = document.getElementById('userRole');
    
    if (usernameElement) {
        usernameElement.textContent = userInfo.username;
    }
    if (userRoleElement) {
        userRoleElement.textContent = userInfo.role;
    }
}