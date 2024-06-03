import streamlit as st
import pandas as pd
import binascii
import bcrypt
import datetime
import phonenumbers
from github_contents import GithubContents
from PIL import Image

# Constants
DATA_FILE = "MyLoginTable.csv"
DATA_COLUMNS = ['username', 'name', 'birthday', 'password']

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
            
        # Ensure phone number columns are treated as strings
        st.session_state.df_users['emergency_contact_number'] = st.session_state.df_users['emergency_contact_number'].astype(str)

def register_page():
    """ Register a new user. """
    logo_path = "Logo.jpeg"  
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Register")
    with st.form(key='register_form'):
        st.write("Please fill in the following details:")
        new_first_name = st.text_input("First Name")
        new_last_name = st.text_input("Last Name")
        new_username = st.text_input("Username")
        new_birthday = st.date_input("Birthday", min_value=datetime.date(1900, 1, 1))
        new_password = st.text_input("Password", type="password")
        
        submit_button = st.form_submit_button("Register")
        if submit_button:
            if new_username in st.session_state.df_users['username'].values:
                st.error("Username already exists. Please choose a different one.")
                return
            else:
                # Hash the password
                hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
                hashed_password_hex = binascii.hexlify(hashed_password).decode()
                
                # Create a new user DataFrame
                new_user_data = [[new_username, f"{new_first_name} {new_last_name}", new_birthday, hashed_password_hex]]
                new_user = pd.DataFrame(new_user_data, columns=DATA_COLUMNS)
                
                # Link the new user DataFrame with the existing one
                st.session_state.df_users = pd.concat([st.session_state.df_users, new_user], ignore_index=True)
                
                # Write updated dataframe to GitHub data repository
                try:
                    st.session_state.github.write_df(DATA_FILE, st.session_state.df_users, "added new user")
                    st.success("Registration successful! You can now log in.")
                    st.switch_page("pages/3_Profile.py")
                except GithubContents.UnknownError as e:
                    st.error(f"An unexpected error occurred: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")

def login_page():
    """ Login an existing user. """
    logo_path = "Logo.jpeg"
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Login")
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            authenticate(username, password)
            st.switch_page("pages/3_Profile.py")

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
        
        if bcrypt.checkpw(password.encode('utf8'), stored_hashed_password_bytes): 
            st.session_state['authentication'] = True
            st.session_state['username'] = username
            st.success('Login successful')
            st.switch_page("pages/3_Profile.py")
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

def main():
    init_github()
    init_credentials()
    
    if 'authentication' not in st.session_state:
        st.session_state['authentication'] = False

    if not st.session_state['authentication']:
        options = st.sidebar.selectbox("Select a page", ["Login", "Register"])
        st.sidebar.write("_Please reload Website if you just logged out_")
        if options == "Login":
            login_page()
        elif options == "Register":
            register_page()
    else:
        logo_path = "Logo.jpeg"  
        st.image(logo_path, use_column_width=True)
        st.write("---")
        st.write("### You are already logged in")
        show_gif() # Defined Gif will be displayed if meeting the conditions
        
        st.sidebar.write(f"Logged in as {st.session_state['username']}")
        
        # Retrieve the emergency contact information from the DataFrame
        user_data = st.session_state.df_users.loc[st.session_state.df_users['username'] == st.session_state['username']]
        if not user_data.empty:
            st.session_state['emergency_contact_name'] = user_data['emergency_contact_name'].iloc[0] if 'emergency_contact_name' in user_data.columns else ''
            st.session_state['emergency_contact_number'] = user_data['emergency_contact_number'].iloc[0] if 'emergency_contact_number' in user_data.columns else ''

        if st.sidebar.button("Logout"):
            st.session_state['authentication'] = False
            st.session_state.pop('username', None)
            st.switch_page("Main.py")
            
        st.sidebar.write("_Please reload Website after logging out_")

        display_emergency_contact()

def show_gif():
    gif_url = "https://media.tenor.com/5SMdPfjBuXwAAAAi/tomrobinson-tylastephens.gif"
    gif_html = f'<img src="{gif_url}" style="width:100%;">'
    st.markdown(gif_html, unsafe_allow_html=True)

def format_phone_number(number):
    """Format phone number using phonenumbers library."""
    if not number or pd.isna(number) or number == 'nan':
        return None
    number_str = str(number).strip()
    if number_str.endswith('.0'):
        number_str = number_str[:-2]
    try:
        phone_number = phonenumbers.parse(number_str, "CH")
        if phonenumbers.is_valid_number(phone_number):
            return phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
        else:
            return number_str
    except phonenumbers.NumberParseException:
        return number_str

def display_emergency_contact():
        """Display the emergency contact in the sidebar if it exists."""
    if 'emergency_contact_name' in st.session_state and 'emergency_contact_number' in st.session_state:
        emergency_contact_name = st.session_state['emergency_contact_name']
        emergency_contact_number = st.session_state['emergency_contact_number']

        if emergency_contact_number:
            formatted_emergency_contact_number = format_phone_number(emergency_contact_number)
            st.sidebar.write(f"Emergency Contact: {emergency_contact_name}")
            
            if formatted_emergency_contact_number:
                st.sidebar.markdown(f"[{formatted_emergency_contact_number}](tel:{formatted_emergency_contact_number})")
            else:
                st.sidebar.write("No valid emergency contact number available.")
        else:
            st.sidebar.write("No emergency contact number available.")
    else:
        st.sidebar.write("No emergency contact information available.")

if __name__ == "__main__":
    main()
