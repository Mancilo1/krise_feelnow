import streamlit as st
import bcrypt
import binascii
import pytz
import datetime
import pandas as pd
from github_contents import GithubContents

# Constants
DATA_FILE = "MyLoginTable.csv"
DATA_COLUMNS = ['username', 'name', 'password']

def main():
    init_github()
    init_credentials()

    if 'authentication' not in st.session_state:
        st.session_state['authentication'] = False

    if not st.session_state['authentication']:
        options = st.sidebar.selectbox("Select a page", ["Login", "Register"])
        if options == "Login":
            login_page()
        elif options == "Register":
            register_page()
    else:
        st.sidebar.write(f"Logged in as {st.session_state['username']}")
        anxiety_attack_protocol()

        logout_button = st.sidebar.button("Logout")
        if logout_button:
            st.session_state['authentication'] = False
            st.session_state.pop('username', None)
            st.switch_page("Main.py")
            st.experimental_rerun()

def anxiety_attack_protocol():
    username = st.session_state['username']
    data_file = f"{username}_attack_data.csv"
    
    if 'data' not in st.session_state:
        if st.session_state.github.file_exists(data_file):
            st.session_state.data = st.session_state.github.read_df(data_file)
        else:
            st.session_state.data = pd.DataFrame(columns=['Date', 'Time', 'Severity', 'Listed Symptoms','New Symptoms', 'Triggers', 'New Triggers', 'Help'])

    st.title("Anxiety Attack Protocol")

    # Question 1: Date
    date_selected = st.date_input("Date", value=datetime.date.today())

    # Question 2: Time & Severity
    add_time_severity()

    # Question 3: Symptoms
    st.subheader("Symptoms:")
    symptoms_list = []
    col1, col2 = st.columns(2)
    with col1:
        if st.checkbox("Anxiety"): symptoms_anxiety.append("Anxiety")
        if st.checkbox("Chest Pain"): symptoms_list.append("Chest Pain")
        if st.checkbox("Chills"): symptoms_list.append("Chills")
        if st.checkbox("Chocking"): symptoms_list.append("Chocking")
        if st.checkbox("Cold"): symptoms_list.append("Cold")
        if st.checkbox("Cold Hands"): symptoms_list.append("Cold Hands")
        if st.checkbox("Dizziness"): symptoms_list.append("Dizziness")
        if st.checkbox("Feeling of danger"): symptoms_list.append("Feeling of danger")
        if st.checkbox("Feeling of dread"): symptoms_list.append("Feeling of dread")
        if st.checkbox("Heart racing"): symptoms_list.append("Heart racing")
        if st.checkbox("Hot flushes"): symptoms_list.append("Hot flushes")
        if st.checkbox("Irrational thinking"): symptoms_list.append("Irrational thinking")
    with col2:
        if st.checkbox("Nausea"): symptoms_list.append("Nausea")
        if st.checkbox("Nervousness"): symptoms_list.append("Nervousness")
        if st.checkbox("Numb Hands"): symptoms_list.append("Numb Hands")
        if st.checkbox("Numbness"): symptoms_list.append("Numbness")
        if st.checkbox("Palpitations"): symptoms_list.append("Palpitations")
        if st.checkbox("Shortness of Breath"): symptoms_list.append("Shortness of Breath")
        if st.checkbox("Sweating"): symptoms_list.append("Sweating")
        if st.checkbox("Tense Muscles"): symptoms_list.append("Tense Muscles")
        if st.checkbox("Tingly Hands"): symptoms_list.append("Tingly Hands")
        if st.checkbox("Trembling"): symptoms_list.append("Trembling")
        if st.checkbox("Tremor"): symptoms_list.append("Tremor")
        if st.checkbox("Weakness"): symptoms_list.append("Weakness")
    
    if 'symptoms' not in st.session_state:
        st.session_state.symptoms = []

    for symptoms in st.session_state.symptoms:
        st.write(symptoms)

    st.subheader("Any Symptoms that are not listed?")
    new_symptoms = st.text_area("Write your response here", key="new_symptoms", height=50)

    # Question 4: Triggers
    st.subheader("Triggers:")
    triggers = st.multiselect("Select Triggers", ["Stress", "Caffeine", "Lack of Sleep", "Social Event", "Reminder of traumatic event", "Alcohol", "Conflict", "Family problems"])
    
    if 'triggers' not in st.session_state:
        st.session_state.triggers = []

    for trigger in st.session_state.triggers:
        st.write(trigger)

    st.subheader("Any Triggers that are not listed?")
    new_triggers = st.text_area("Write your response here", key="new_triggers", height=20)

    # Question 5: Did something Help against the attack?
    st.subheader("Did something Help against the attack?")
    help_response = st.text_area("Write your response here", height=100)

    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        if st.button("Save Entry"):
            new_entry = {
                'Date': date_selected,
                'Time': [entry['time'] for entry in st.session_state.time_severity_entries],
                'Severity': [entry['severity'] for entry in st.session_state.time_severity_entries],
                'Listed Symptoms': symptoms,
                'New Symptoms': new_symptoms,
                'Triggers': triggers,
                'New Triggers': new_triggers,
                'Help': help_response
            }
            # Create a DataFrame from the new entry
            new_entry_df = pd.DataFrame([new_entry])
        
            # Append the new entry to the existing data DataFrame
            st.session_state.data = pd.concat([st.session_state.data, new_entry_df], ignore_index=True)
        
            # Save the updated DataFrame to the user's specific CSV file on GitHub
            st.session_state.github.write_df(data_file, st.session_state.data, "added new entry")
            st.success("Entry saved successfully!")

            # Clear the severity entries after saving
            st.session_state.time_severity_entries = []
    with col2:
        if st.button("Back to My Profile"):
            st.switch_page("pages/3_Profile.py")

def add_time_severity():
    if 'time_severity_entries' not in st.session_state:
        st.session_state.time_severity_entries = []

    st.subheader("Time & Severity")

    # Display the current time
    current_time = datetime.datetime.now(pytz.timezone('Europe/Zurich')).strftime('%H:%M')
    st.write(f"Current Time: {current_time}")

    # Button to add a new time-severity entry
    with st.form(key='severity_form'):
        severity = st.slider("Severity (1-10)", min_value=1, max_value=10, key=f"severity_slider")
        if st.form_submit_button("Add Severity"):
            new_entry = {
                'time': current_time,
                'severity': severity
            }
            st.session_state.time_severity_entries.append(new_entry)
            st.success(f"Added entry: Time: {current_time}, Severity: {severity}")

    # Display all time-severity entries
    for entry in st.session_state.time_severity_entries:
        st.write(f"Time: {entry['time']}, Severity: {entry['severity']}")

def init_github():
    """Initialize the GithubContents object."""
    if 'github' not in st.session_state:
        st.session_state.github = GithubContents(
            st.secrets["github"]["owner"],
            st.secrets["github"]["repo"],
            st.secrets["github"]["token"])
        print("github initialized")
    
def init_credentials():
    """Initialize or load the dataframe."""
    if 'df_users' not in st.session_state:
        if st.session_state.github.file_exists(DATA_FILE):
            st.session_state.df_users = st.session_state.github.read_df(DATA_FILE)
        else:
            st.session_state.df_users = pd.DataFrame(columns=DATA_COLUMNS)

def login_page():
    """Login an existing user."""
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Login")
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            authenticate(username, password)

def register_page():
    """Register a new user."""
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Register")
    with st.form(key='register_form'):
        new_username = st.text_input("New Username")
        new_name = st.text_input("Name")
        new_password = st.text_input("New Password", type="password")
        if st.form_submit_button("Register"):
            hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())  # Hash the password
            hashed_password_hex = binascii.hexlify(hashed_password).decode()  # Convert hash to hexadecimal string
            
            # Check if the username already exists
            if new_username in st.session_state.df_users['username'].values:
                st.error("Username already exists. Please choose a different one.")
                return
            else:
                new_user = pd.DataFrame([[new_username, new_name, hashed_password_hex]], columns=DATA_COLUMNS)
                st.session_state.df_users = pd.concat([st.session_state.df_users, new_user], ignore_index=True)
                
                # Writes the updated dataframe to GitHub data repository
                st.session_state.github.write_df(DATA_FILE, st.session_state.df_users, "added new user")
                st.success("Registration successful! You can now log in.")

def authenticate(username, password):
    """
    Authenticate the user.

    Parameters:
    username (str): The username to authenticate.
    password (str): The password to authenticate.
    """
    login_df = st.session_state.df_users
    login_df['username'] = login_df['username'].astype(str)

    if username in login_df['username'].values:
        stored_hashed_password = login_df.loc[login_df['username'] == username, 'password'].values[0]
        stored_hashed_password_bytes = binascii.unhexlify(stored_hashed_password)  # Convert hex to bytes
        
        # Check the input password
        if bcrypt.checkpw(password.encode('utf8'), stored_hashed_password_bytes): 
            st.session_state['authentication'] = True
            st.session_state['username'] = username
            st.success('Login successful')
            st.experimental_rerun()
        else:
            st.error('Incorrect password')
    else:
        st.error('Username not found')

def switch_page(page_name):
    st.success(f"Redirecting to {page_name.replace('_', ' ')} page...")
    time.sleep(3)
    st.experimental_set_query_params(page=page_name)
    st.experimental_rerun()

if __name__ == "__main__":
    main()
