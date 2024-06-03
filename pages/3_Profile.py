import streamlit as st
import binascii
import bcrypt
import time
import pandas as pd
from github_contents import GithubContents
from PIL import Image
import datetime
import phonenumbers

# Constants
DATA_FILE = "MyLoginTable.csv"
DATA_COLUMNS = ['username', 'name', 'birthday', 'password', 'address', 'occupation', 'email', 'doctor', 'doctor_email', 'emergency_contact_name', 'emergency_contact_number']

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

def login_page():
    """ Login an existing user. """
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Login")
    with st.form(key='login_form'):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            authenticate(username, password)
            if st.session_state['authentication']:
                st.switch_page("pages/3_Profile.py")

def register_page():
    """ Register a new user. """
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Register")
    with st.form(key='register_form'):
        new_username = st.text_input("New Username")
        new_name = st.text_input("Name")
        new_birthday = st.date_input("Birthday", min_value=datetime.date(1900, 1, 1))
        new_address = st.text_area("Address")
        new_occupation = st.text_input("Occupation")
        new_email = st.text_input("Email")
        new_doctor = st.text_input('Doctor')
        new_doctor_email = st.text_input("Doctor's Email")
        new_emergency_contact_name = st.text_input("Emergengy Contact Name")
        new_emergency_contact_number = st.text_input("Emergency Contact Number")
        new_password = st.text_input("New Password", type="password")
        if st.form_submit_button("Register"):
            hashed_password = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            hashed_password_hex = binascii.hexlify(hashed_password).decode()
            
            if new_username in st.session_state.df_users['username'].values:
                st.error("Username already exists. Please choose a different one.")
            else:
                new_user = pd.DataFrame([[new_username, new_name, new_birthday, hashed_password_hex, new_address, new_occupation, new_email, new_doctor, new_doctor_email, new_emergency_contact_name, new_emergency_contact_number]], columns=DATA_COLUMNS)
                st.session_state.df_users = pd.concat([st.session_state.df_users, new_user], ignore_index=True)
                st.session_state.df_users['emergency_contact_number'] = st.session_state.df_users['emergency_contact_number'].astype(str)
                st.session_state.github.write_df(DATA_FILE, st.session_state.df_users, "added new user")
                st.success("Registration successful! You can now log in.")

def authenticate(username, password):
    """ Authenticate the user. """
    login_df = st.session_state.df_users
    login_df['username'] = login_df['username'].astype(str)

    if username in login_df['username'].values:
        stored_hashed_password = login_df.loc[login_df['username'] == username, 'password'].values[0]
        stored_hashed_password_bytes = binascii.unhexlify(stored_hashed_password)
        
        if bcrypt.checkpw(password.encode('utf8'), stored_hashed_password_bytes): 
            st.session_state['authentication'] = True
            st.session_state['username'] = username
            st.success('Login successful')
            st.experimental_rerun()
        else:
            st.error('Incorrect password')
    else:
        st.error('Username not found')

def main_page():
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Your Anxiety Tracker Journal")
    st.subheader("Profile")
    
    if 'username' in st.session_state:
        username = st.session_state['username']

        # Load user data
        user_data = st.session_state.df_users.loc[st.session_state.df_users['username'] == username]

        if not user_data.empty:
            if 'edit_profile' not in st.session_state:
                st.session_state.edit_profile = False

            if st.session_state.edit_profile:
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Name:", value=user_data['name'].iloc[0])
                    occupation = st.text_input("Occupation:", value=user_data['occupation'].iloc[0] if 'occupation' in user_data.columns else '')
                    doctor = st.text_input("Doctor:", value=user_data['doctor'].iloc[0] if 'doctor' in user_data.columns else '')
                    doctor_email = st.text_input("Doctor's Email:", value=user_data['doctor_email'].iloc[0] if 'doctor_email' in user_data.columns else '')
                    emergency_contact_name = st.text_input("Emergency Contact Name:", value=user_data['emergency_contact_name'].iloc[0] if 'emergency_contact_name' in user_data.columns else '')

                with col2:
                    birthday = st.date_input("Birthday:", value=pd.to_datetime(user_data['birthday'].iloc[0]))
                    address = st.text_area("Address:", value=user_data['address'].iloc[0] if 'address' in user_data.columns else '')
                    email = st.text_input("Email:", value=user_data['email'].iloc[0] if 'email' in user_data.columns else '')
                    emergency_contact_number = st.text_input("Emergency Contact Number:", value=user_data['emergency_contact_number'].astype(str).iloc[0] if 'emergency_contact_number' in user_data.columns else '')

                if st.button("Save Changes"):
                    formatted_emergency_contact_number = format_phone_number(emergency_contact_number)
                    
                    #  Save or clear emergency contact number if empty
                    if formatted_emergency_contact_number is not None:
                        st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'emergency_contact_number'] = formatted_emergency_contact_number
                    else:
                        st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'emergency_contact_number'] = ''

                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'name'] = name
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'birthday'] = birthday
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'address'] = address
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'occupation'] = occupation
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'email'] = email
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'doctor'] = doctor
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'doctor_email'] = doctor_email
                    st.session_state.df_users.loc[st.session_state.df_users['username'] == username, 'emergency_contact_name'] = emergency_contact_name

                    # Ensure phone number columns are treated as strings
                    st.session_state.df_users['emergency_contact_number'] = st.session_state.df_users['emergency_contact_number'].astype(str)

                    st.session_state.github.write_df(DATA_FILE, st.session_state.df_users, "updated user data")
                    st.success("Profile updated successfully!")
                    st.session_state.edit_profile = False
                    st.experimental_rerun()

                if st.button("Cancel"):
                    st.session_state.edit_profile = False
                    st.experimental_rerun()
            else:
                col1, col2 = st.columns(2)
                with col1:
                    st.write("Name:", user_data['name'].iloc[0])
                    st.write("Occupation:", user_data['occupation'].iloc[0] if 'occupation' in user_data.columns else '')
                    st.write("Doctor:", user_data['doctor'].iloc[0] if 'doctor' in user_data.columns else '')
                    st.write("Doctor's Email:", user_data['doctor_email'].iloc[0] if 'doctor_email' in user_data.columns else '')
                    st.write("Emergency Contact Name:", user_data['emergency_contact_name'].iloc[0] if 'emergency_contact_name' in user_data.columns else '')

                with col2:
                    st.write("Birthday:", user_data['birthday'].iloc[0])
                    st.write("Address:", user_data['address'].iloc[0] if 'address' in user_data.columns else '')
                    st.write("Email:", user_data['email'].iloc[0] if 'email' in user_data.columns else '')
                    st.write("Emergency Contact Number:", format_phone_number(user_data['emergency_contact_number'].astype(str).iloc[0]) if 'emergency_contact_number' in user_data.columns else '')
                
                if st.button("Edit Profile"):
                    st.session_state.edit_profile = True
                    st.experimental_rerun()
        else:
            st.error("User data not found.")
    else:
        st.error("User not logged in.")
        if st.button("Login/Register"):
            st.switch_page("pages/2_Login.py")

def format_phone_number(number):
    """Format phone number using phonenumbers library."""
    if not number or pd.isna(number) or number == 'nan':
        return None
    number_str = str(number).strip()
    if number_str.endswith('.0'):
        number_str = number_str[:-2]  # Remove trailing '.0'
    try:
        phone_number = phonenumbers.parse(number_str, "CH")  # "CH" is for Switzerland
        if phonenumbers.is_valid_number(phone_number):
            return phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
        else:
            return number_str  # Return the original number if invalid
    except phonenumbers.NumberParseException:
        return number_str  # Return the original number if parsing fails

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

def anxiety_assessment():
    st.title("Anxiety Assessment")
    
    if "step" not in st.session_state:
        st.session_state.step = 1

    if st.session_state.step == 1:
        st.write("### Do you feel like you're having an Anxiety Attack right now?")
        if st.button("Yes"):
            st.switch_page("pages/4_Anxiety_Attack_Protocol.py")
        if st.button("No"):
            st.session_state.step = 2
            st.experimental_rerun()

    if st.session_state.step == 2:
        st.write("### Are you anxious right now?")
        if st.button("Yes "):
            st.switch_page("pages/5_Anxiety_Protocol.py")
        if st.button("No "):
            st.session_state.step = 3
            st.experimental_rerun()

    if st.session_state.step == 3:
        show_gif()
        if st.button("Reassess your feelings"):
            st.session_state.step = 1
            st.experimental_rerun()

def show_gif():
    gif_url = "https://64.media.tumblr.com/28fad0005f6861c08f2c07697ff74aa4/tumblr_n4y0patw7Q1rn953bo1_500.gif"
    gif_html = f'<img src="{gif_url}" style="width:100%;">'
    st.markdown(gif_html, unsafe_allow_html=True)
    
def show_saved_entries():
    st.subheader("Saved Entries from Anxiety Attack Protocol")
    username = st.session_state['username']
    data_file_attack = f"{username}_anxiety_attack_data.csv"
    data_file_anxiety = f"{username}_anxiety_protocol_data.csv"
    
    if st.session_state.github.file_exists(data_file_attack):
        anxiety_attack_data = st.session_state.github.read_df(data_file_attack)
        st.write(anxiety_attack_data)
    else:
        st.write("No saved entries from Anxiety Attack Protocol.")
    
    st.subheader("Saved Entries from Anxiety Protocol")
    if st.session_state.github.file_exists(data_file_anxiety):
        anxiety_protocol_data = st.session_state.github.read_df(data_file_anxiety)
        st.write(anxiety_protocol_data)
    else:
        st.write("No saved entries from Anxiety Protocol.")

def german_protocols():
    st.title("German Protocols")
    st.subheader("Anxiety Attack Protocol")
    st.write("Click on the button to download the german version.")
    st.write("Um die Deutsche PDF version des 'Anxiety Attack Protocol' herunterzuladen, auf 'Download Panickattacke Protokoll' klicken.")
    with open("Panickattacke Protokoll.pdf", "rb") as pdf_file:
        pdf_bytes = pdf_file.read()
        st.download_button(
            label="Download Panickattacke Protokoll",
            data=pdf_bytes,
            file_name="Panickattacke Protokoll.pdf",
            mime="application/pdf",
            key="download_panic_protocol"
        )
    st.write("---")
    st.subheader("Anxiety Protocol")
    st.write("Click on the button to download the german version.")
    st.write("Um die Deutsche PDF version des 'Anxiety Protocol' herunterzuladen, auf 'Download Angstprotokoll' klicken.")
    with open("Angstprotokoll.pdf", "rb") as pdf_file:
        pdf_bytes = pdf_file.read()
        st.download_button(
            label="Download Angstprotokoll",
            data=pdf_bytes,
            file_name="Angstprotokoll.pdf",
            mime="application/pdf",
            key="download_anxiety_protocol"
        )

def switch_page(page_name):
    st.success(f"Redirecting to {page_name.replace('_', ' ')} page...")
    st.experimental_set_query_params(page=page_name)
    time.sleep(3)
    st.experimental_rerun()

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
        st.sidebar.write("Please reload Website after logging out")
        # Retrieve the emergency contact information from the DataFrame
        user_data = st.session_state.df_users.loc[st.session_state.df_users['username'] == st.session_state['username']]
        if not user_data.empty:
            st.session_state['emergency_contact_name'] = user_data['emergency_contact_name'].iloc[0] if 'emergency_contact_name' in user_data.columns else ''
            st.session_state['emergency_contact_number'] = user_data['emergency_contact_number'].iloc[0] if 'emergency_contact_number' in user_data.columns else ''

        main_page()
        st.write("---")
        anxiety_assessment()
        st.write("---")
        german_protocols()
        st.write("---")
        show_saved_entries()
        
        if st.sidebar.button("Logout"):
            st.session_state['authentication'] = False
            st.session_state.pop('username', None)
            st.switch_page("Main.py")
            
        st.sidebar.write("_Please reload Website after logging out_")
    
    display_emergency_contact()

if __name__ == "__main__":
    main()
