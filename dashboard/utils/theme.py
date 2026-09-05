import streamlit as st

def apply_theme() -> None:
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
        
        /* Apply clean font to the entire Streamlit screen */
        html, body, [class*="css"], .stApp {
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif !important;
            background-color: #f8fafc !important;
            color: #0f172a !important;
        }
        
        code, pre, .evidence-json {
            font-family: 'JetBrains Mono', monospace !important;
        }
        
        /* Glassmorphic/SaaS Cards configuration */
        div[data-testid="stMetric"] {
            background-color: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 12px !important;
            padding: 16px 20px !important;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05) !important;
            transition: border-color 0.25s ease, transform 0.25s ease, box-shadow 0.25s ease !important;
        }
        
        div[data-testid="stMetric"]:hover {
            border-color: #2563eb !important;
            transform: translateY(-2px) !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05) !important;
        }
        
        div[data-testid="stMetricLabel"] > div {
            color: #475569 !important;
            font-size: 0.8rem !important;
            font-weight: 600 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.05em !important;
        }
        
        div[data-testid="stMetricValue"] > div {
            color: #0f172a !important;
            font-size: 1.9rem !important;
            font-weight: 700 !important;
            letter-spacing: -0.03em;
        }
        
        /* Custom styled headings */
        h3 {
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            color: #0f172a !important;
            letter-spacing: -0.02em;
            margin-top: 20px !important;
            margin-bottom: 12px !important;
        }
        
        /* Light styled card component */
        .saas-card {
            background-color: #ffffff !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 12px !important;
            padding: 24px !important;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05) !important;
            margin-bottom: 20px !important;
        }
        
        /* Code styling block */
        pre {
            border-radius: 8px !important;
            border: 1px solid #e2e8f0 !important;
            background-color: #f1f5f9 !important;
            color: #0f172a !important;
        }
        
        /* Sidebar styling override */
        section[data-testid="stSidebar"] {
            background-color: #ffffff !important;
            border-right: 1px solid #e2e8f0 !important;
        }
        
        /* Table headers */
        .stTable th {
            background-color: #f1f5f9 !important;
            color: #475569 !important;
            font-weight: 600 !important;
        }

        /* Prevent Streamlit from dimming elements/widgets during page reruns */
        div[data-stale="true"] {
            opacity: 1 !important;
            filter: none !important;
        }

        /* Modern Sidebar Navigation Pill Style */
        section[data-testid="stSidebar"] [data-testid="stRadio"] > div {
            gap: 6px !important;
        }

        section[data-testid="stSidebar"] [data-testid="stRadio"] label {
            background-color: #f8fafc !important;
            border: 1px solid #e2e8f0 !important;
            border-radius: 10px !important;
            padding: 8px 14px !important;
            margin-bottom: 2px !important;
            transition: all 0.18s ease-in-out !important;
            cursor: pointer !important;
            font-weight: 500 !important;
            color: #334155 !important;
        }

        section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
            background-color: #eff6ff !important;
            border-color: #93c5fd !important;
            color: #1d4ed8 !important;
            transform: translateX(2px) !important;
        }

        section[data-testid="stSidebar"] [data-testid="stRadio"] label[data-checked="true"],
        section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
            background-color: #2563eb !important;
            border-color: #2563eb !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            box-shadow: 0 2px 4px 0 rgba(37, 99, 235, 0.25) !important;
        }

        section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) p {
            color: #ffffff !important;
        }

        /* Modern Selectbox & Controls in Sidebar */
        section[data-testid="stSidebar"] div[data-baseweb="select"] {
            border-radius: 8px !important;
        }
        
        section[data-testid="stSidebar"] button {
            border-radius: 8px !important;
            font-weight: 600 !important;
        }
        </style>
    """, unsafe_allow_html=True)
