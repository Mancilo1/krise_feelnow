import streamlit as st
import pandas as pd
import binascii
import bcrypt
import time
from github_contents import GithubContents
from deep_translator import GoogleTranslator  # Import the GoogleTranslator class from the deep_translator library
from PIL import Image

# Initialize session state if not already done
if 'language' not in st.session_state:
    st.session_state.language = "English"  # Default language

# Initialize the GithubContents object
if 'github' not in st.session_state:
    st.session_state.github = GithubContents(
        st.secrets["github"]["owner"],
        st.secrets["github"]["repo"],
        st.secrets["github"]["token"])
    print("github initialized")

# Initialize user credentials dataframe if not already done
if 'df_users' not in st.session_state:
    if st.session_state.github.file_exists("MyLoginTable.csv"):
        st.session_state.df_users = st.session_state.github.read_df("MyLoginTable.csv")
    else:
        st.session_state.df_users = pd.DataFrame(columns=['username', 'name', 'password'])

def main():
    # Display the logo image with responsive width
    logo_path = "Logo.jpeg"  # Ensure this path is correct relative to your script location
    st.image(logo_path, use_column_width=True)
    st.write("---")

    languages = {
        "English": "en",
        "German": "de",
    }

    # Language selection
    selected_language = st.sidebar.selectbox("Choose your language", list(languages.keys()), index=list(languages.keys()).index(st.session_state.language))
    st.session_state.language = selected_language
    target_language = languages[selected_language]
    st.title("Anxiety Tracker Journal")

    original_text = (
        "Welcome to FeelNow, your anxiety attack journal. "
        "This app helps you track and manage your anxiety by providing a platform to journal your thoughts "
        "and feelings during anxiety attacks.\n\n"
        "## What is FeelNow\n"
        "FeelNow is an app with which you can easily assess and monitor an acute panic attack. It is just like a diary and helps you to keep an eye on your mental health.\n\n"
        "## What can the App do\n"
        "The app is supposed to help you write down important parts of a panic attack or even simply for your anxiety. It simplifies taking notes while feeling distressed by having the option to just choose how you're feeling instead of having to write your feelings down yourself.\n\n"
        "## How do I use it\n"
        "You can create your own login by registering. You will then have a list of important points to assess during an acute attack, such as symptoms, possible triggers, who helped you at that moment or how strongly you felt them. If you do not feel like you're having a panic attack but you do feel anxious, you can do the same in the simpler version.\n\n"
        "## About this App\n"
        "This app is mainly used in English. If needed, there are files available for download after you have successfully logged in, which display the anxiety assessment protocols in German. You can use them as a reference and to help use the app, even if it is not in German. If you are not registered or logged in, you will not have access to the profile page and the anxiety assessment protocols. Once you are logged in, you will be redirected to your profile, where you will have access to your entries, personal data, and the anxiety assessment questions. You can use these questions or go directly to the anxiety assessment protocols if needed. You can log out anytime using the sidebar.\n\n"
        "## Information\n"
        "By clicking on 'Information' in the sidebar menu, you have the possibility to inform yourself about mental health and anxiety disorders, as well as to look up some helpful tricks for your anxiety."
    )
    
    # Translate the text
    translated_text = translate_text(original_text, target_language)
    st.write(translated_text)

    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        if st.button("Go to Information page"):
            st.switch_page("pages/1_Information.py")
    with col2:
        if st.button("Login/Register"):
            st.switch_page("pages/2_Login.py")
        st.sidebar.write("_Please reload Website if you just logged out_")
        st.sidebar.write("_If you didn't logout yet, make sure to do it before closing Website_")

def translate_text(text, target_language):
    translator = GoogleTranslator(target=target_language)  # Initialize the GoogleTranslator object
    translation = translator.translate(text)  # Translate the text
    return translation

def switch_page(page_name):
    st.success(f"Redirecting to {page_name.replace('_', ' ')} page...")
    time.sleep(3)
    st.experimental_set_query_params(page=page_name)
    st.experimental_rerun()

if __name__ == "__main__":
    main()
