import streamlit as st
import pandas as pd
from PIL import Image

def switch_page(page_name):
    st.success(f"Redirecting to {page_name.replace('_', ' ')} page...")
    time.sleep(3)
    st.experimental_set_query_params(page=page_name)
    st.experimental_rerun()

def main():
    logo_path = "Logo.jpeg"
    st.image(logo_path, use_column_width=True)
    st.write("---")
    st.title("Information about Mental Health")

    # Link to Article 1 about Mental Health
    st.write("## Anxiety Disorder")
    st.write("### National Institution of Mental Health")
    st.markdown(""" 
    What is anxiety?
    Occasional anxiety is a normal part of life. Many people worry about things such as health, money, or family problems. But anxiety disorders involve more than temporary worry or fear. For people with an anxiety disorder, the anxiety does not go away and can get worse over time. The symptoms can interfere with daily activities such as job performance, schoolwork, and relationships.
    
    There are several types of anxiety disorders, including generalized anxiety disorder, panic disorder, social anxiety disorder, and various phobia-related disorders. 
    """)
    st.markdown('<a href="https://www.nimh.nih.gov/health/topics/anxiety-disorders" target="_blank"><button>Read more</button></a>', unsafe_allow_html=True)

    # Link to Article 2 about Mental Health
    st.write("## Anxiety Disorder")
    st.write("### World Health Organisation")
    st.markdown("""
    Everyone can feel anxious sometimes, but people with anxiety disorders often experience fear and worry that is both intense and excessive. These feelings are typically accompanied by physical tension and other behavioural and cognitive symptoms. They are difficult to control, cause significant distress and can last a long time if untreated. Anxiety disorders interfere with daily activities and can impair a person’s family, social and school or working life.

    An estimated 4% of the global population currently experience an anxiety disorder (1). In 2019, 301 million people in the world had an anxiety disorder, making anxiety disorders the most common of all mental disorders (1).

    Although highly effective treatments for anxiety disorders exist, only about 1 in 4 people in need (27.6%) receive any treatment (2). Barriers to care include lack of awareness that this is a treatable health condition, lack of investment in mental health services, lack of trained health care providers, and social stigma.
    """)
    st.markdown('<a href="https://www.who.int/news-room/fact-sheets/detail/anxiety-disorders" target="_blank"><button>Read more</button></a>', unsafe_allow_html=True)

    # Link to Article 3 about Mental Health
    st.write("## 11 tips for coping with an anxiety disorder")
    st.markdown("""
    Keep physically active.
    Develop a routine so that you're physically active most days of the week. Exercise is a powerful stress reducer. It can improve your mood and help you stay healthy. Start out slowly, and gradually increase the amount and intensity of your activities.
    Avoid alcohol and recreational drugs.
    These substances can cause or worsen anxiety. If you can't quit on your own, see your healthcare provider or find a support group to help you.
    Quit smoking, and cut back or quit drinking caffeinated beverages.
    Nicotine and caffeine can worsen anxiety.
    """)
    st.markdown('<a href="https://www.mayoclinichealthsystem.org/hometown-health/speaking-of-health/11-tips-for-coping-with-an-anxiety-disorder" target="_blank"><button>Read more</button></a>', unsafe_allow_html=True)
        
    # Link to Article 4 about Mental Health
    st.write("## I Feel Anxious: Tips for Dealing with Anxiety")
    st.write("Feeling tense, restless, or fearful? Anxiety can make you feel trapped in your own head, but these tools can help you ease tension, stay present, and manage anxiety.")
    st.markdown(""" 
    Why am I anxious?
    Anxiety can arise for all sorts of reasons. You may feel restless and have a hard time sleeping the night before an important test, an early flight, or a job interview, for example. Or you may feel nauseous when you think about going to a party and interacting with strangers, or physically tense when comparing your bank balance to the bills that keep mounting up.

    Sometimes it can seem that you feel nervous, panicky, and on-edge for no reason at all. However, there’s usually a trigger to feelings of anxiety and panic, even if it’s not immediately obvious.
    """)
    st.markdown('<a href="https://www.helpguide.org/articles/anxiety/i-feel-anxious-tips-for-dealing-with-anxiety.htm" target="_blank"><button>Read more</button></a>', unsafe_allow_html=True)

    col1, col2 = st.columns([0.8, 0.2])
    with col1:
        if st.button("Go back to Mainpage"):
            st.switch_page("Main.py")
    with col2:
        if st.button("Login/Register"):
            st.switch_page("pages/2_Login.py")
        st.sidebar.write("_Please reload Website if you just logged out_")
        st.sidebar.write("_If you didn't logout yet, make sure to do it before closing Website_")

if __name__ == "__main__":
    main()
