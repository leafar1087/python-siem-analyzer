import sys
from unittest.mock import MagicMock

# Mock ollama module BEFORE importing app
sys.modules['ollama'] = MagicMock()

from app import app, db, User

def test_api():
    print("--- TESTING API ENDPOINT ---")
    
    # Create a test client
    with app.test_client() as client:
        # We need to login first
        # Assuming there is a user 'admin' or similar. 
        # Let's find a user first.
        with app.app_context():
            user = User.query.first()
            if not user:
                print("ERROR: No user found to login with.")
                return
            
            print(f"Logging in as: {user.username}")
            # We can't easily login via form without CSRF token handling in test client
            # BUT we can use Flask-Login's login_user if we are in a request context?
            # Or we can bypass login_required for the test?
            # Or we can use a session transaction.
            
            # Simpler: Let's mock the login or use a test_request_context
            pass

    # Actually, simpler approach:
    # We can temporarily disable @login_required in app.py? No.
    # We can manually create a session.
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Manually set the user_id in the session to simulate login
            # Flask-Login uses '_user_id'
            with app.app_context():
                user = User.query.first()
                sess['_user_id'] = str(user.id)
                sess['_fresh'] = True
        
        print("Requesting /api/logs...")
        response = client.get('/api/logs?page=1&per_page=5')
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.get_json()
            print(f"Logs returned: {len(data['logs'])}")
            print(f"Total logs: {data['total_logs']}")
            if len(data['logs']) > 0:
                print("Sample log:", data['logs'][0])
        else:
            print("Response:", response.data)

    print("--- END API TEST ---")

if __name__ == "__main__":
    test_api()
