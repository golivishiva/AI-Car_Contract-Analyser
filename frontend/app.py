# app.py
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
import streamlit as st
from dotenv import load_dotenv
load_dotenv()  # ensure .env is loaded

import os
import re
import json
import tempfile

# Add these imports after your existing imports
from server.auth import init_auth_tables, check_authentication, logout

# Add these lines before st.set_page_config()
init_auth_tables()
check_authentication()

from datetime import datetime
from PIL import Image
from server.lease_parity import calculate_market_monthly_lease

from server.ocr import OCR
from server.summarization import summarize_with_groq
from server.contract_extraction import extract_sla_with_groq
from server.vin_lookup import decode_vin_nhtsa
from server.price_estimator import estimate_price
from server.vector_store import add_document_to_chroma, query_chroma
from server.database import init_db, get_connection

# ✅ STEP 1: Multi-contract session state initialization
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

if "contracts_context" not in st.session_state:
    st.session_state.contracts_context = {}

if "active_contract_id" not in st.session_state:
    st.session_state.active_contract_id = None

# ============================================
# Add this AFTER the imports and AFTER check_authentication()

def load_user_data():
    """Load user's contracts and chat history from database"""
    if 'user_id' not in st.session_state or not st.session_state.user_id:
        return
    
    user_id = st.session_state.user_id
    conn = get_connection()
    cur = conn.cursor()
    
    # Load user's contracts
    cur.execute("""
        SELECT c.id, c.filename, cd.summary, cd.sla, c.created_at
        FROM contracts c
        LEFT JOIN contract_data cd ON c.id = cd.contract_id
        WHERE c.user_id = ?
        ORDER BY c.created_at DESC
    """, (user_id,))
    
    contracts = cur.fetchall()
    
    for contract in contracts:
        contract_id, filename, summary, sla_json, created_at = contract
        
        if contract_id not in st.session_state.contracts_context:
            sla = json.loads(sla_json) if sla_json else {}
            
            vehicle_info = {'vin': None, 'make': None, 'model': None, 'year': None}
            
            if isinstance(sla, dict):
                for k, v in sla.items():
                    if 'vin' in k.lower():
                        vehicle_info['vin'] = v
                    elif 'make' in k.lower():
                        vehicle_info['make'] = v
                    elif 'model' in k.lower():
                        vehicle_info['model'] = v
                    elif 'year' in k.lower():
                        vehicle_info['year'] = v
            
            st.session_state.contracts_context[contract_id] = {
                'filename': filename,
                'summary': summary,
                'sla': sla,
                'vehicle': vehicle_info,
                'market_price': None,
                'contract_price': None,
                'deal_score': None
            }
    
    # Load chat for active contract
    if st.session_state.active_contract_id:
        cur.execute("""
            SELECT role, message, timestamp
            FROM chat_messages
            WHERE contract_id = ? AND user_id = ?
            ORDER BY timestamp ASC
        """, (st.session_state.active_contract_id, user_id))
        
        messages = cur.fetchall()
        if messages and not st.session_state.chat_history:
            st.session_state.chat_history = [
                {"role": row[0], "content": row[1], "timestamp": row[2]}
                for row in messages
            ]
    
    conn.close()

# Call it after check_authentication()
load_user_data()


    

st.set_page_config(page_title="Contract AI - Car Deal Analyzer", layout="centered", page_icon="🚗")

# 🧠 CINEMATIC BACKGROUND STYLING
def get_base64_image(image_path):
    """Convert image to base64 string for embedding in CSS"""
    import base64
    try:
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    except FileNotFoundError:
        return ""

# Get the absolute path to the background image
import pathlib
bg_image_path = pathlib.Path(__file__).parent / "assets" / "bg_car.jpg"
bg_image_base64 = get_base64_image(bg_image_path)

if bg_image_base64:
    st.markdown(
        f"""
        <style>
        /* Full background with blur */
        .stApp {{
            background-image: url("data:image/jpeg;base64,{bg_image_base64}");
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }}

        /* Enhanced dark overlay with blur for better readability */
        .stApp::before {{
            content: "";
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.88) 0%, rgba(0, 0, 0, 0.82) 50%, rgba(0, 0, 0, 0.88) 100%);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            z-index: -1;
        }}

        /* Main content styling with glow */
        .main .block-container {{
            background: rgba(18, 18, 18, 0.75);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border-radius: 24px;
            padding: 2.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5), 0 0 60px rgba(102, 126, 234, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.08);
            animation: fadeInUp 0.8s ease-out;
        }}

        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(30px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        /* Animated gradient text for headers */
        h1 {{
            font-size: 3rem !important;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            background-size: 200% 200%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: gradientShift 3s ease infinite;
            text-shadow: 0 0 40px rgba(102, 126, 234, 0.4);
            font-weight: 800 !important;
            letter-spacing: -0.5px;
        }}

        @keyframes gradientShift {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}

        h2, h3 {{
            text-shadow: 2px 2px 12px rgba(0, 0, 0, 0.95);
            font-weight: 700 !important;
            letter-spacing: 0.3px;
            color: #ffffff !important;
        }}

        /* Paragraph text with enhanced contrast */
        p, li, div {{
            text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.9);
            font-size: 1.08rem;
            line-height: 1.7;
            color: rgba(255, 255, 255, 0.95) !important;
        }}

        /* Animated expanders */
        .streamlit-expanderHeader {{
            background: rgba(30, 30, 30, 0.95) !important;
            border-radius: 14px !important;
            font-weight: 600 !important;
            text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.95);
            border: 1px solid rgba(102, 126, 234, 0.3);
            transition: all 0.3s ease;
        }}

        .streamlit-expanderHeader:hover {{
            background: rgba(40, 40, 40, 0.95) !important;
            border-color: rgba(102, 126, 234, 0.6);
            transform: translateX(5px);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}

        .streamlit-expanderContent {{
            background: rgba(20, 20, 20, 0.98) !important;
            border-radius: 0 0 14px 14px !important;
            padding: 1.8rem !important;
            border: 1px solid rgba(102, 126, 234, 0.2);
            border-top: none;
            animation: slideDown 0.3s ease;
        }}

        @keyframes slideDown {{
            from {{
                opacity: 0;
                max-height: 0;
            }}
            to {{
                opacity: 1;
                max-height: 500px;
            }}
        }}

        /* Enhanced chat input */
        textarea, input {{
            background-color: rgba(30, 30, 30, 0.98) !important;
            color: white !important;
            border-radius: 14px !important;
            border: 1px solid rgba(102, 126, 234, 0.3) !important;
            font-size: 1.05rem !important;
            padding: 14px !important;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4) !important;
            transition: all 0.3s ease !important;
        }}

        textarea:focus, input:focus {{
            border-color: rgba(102, 126, 234, 0.8) !important;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.25) !important;
            outline: none !important;
            transform: scale(1.01);
        }}

        /* Animated chat bubbles */
        .stChatMessage {{
            background: rgba(30, 30, 30, 0.98) !important;
            border-radius: 18px;
            padding: 18px;
            margin-bottom: 14px;
            border: 1px solid rgba(102, 126, 234, 0.25);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
            animation: messageSlideIn 0.4s ease-out;
        }}

        @keyframes messageSlideIn {{
            from {{
                opacity: 0;
                transform: translateX(-20px);
            }}
            to {{
                opacity: 1;
                transform: translateX(0);
            }}
        }}

        /* 🚀 ROCKET LAUNCH BUTTON with animation */
        .stButton > button {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 16px;
            padding: 1rem 2.5rem;
            font-weight: 700;
            font-size: 1.2rem;
            text-shadow: 1px 1px 3px rgba(0, 0, 0, 0.6);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
            transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            position: relative;
            overflow: hidden;
        }}

        .stButton > button::before {{
            content: "";
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }}

        .stButton > button:hover {{
            transform: translateY(-4px) scale(1.05);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.7);
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }}

        .stButton > button:hover::before {{
            width: 300px;
            height: 300px;
        }}

        .stButton > button:active {{
            transform: translateY(-2px) scale(1.02);
        }}

        /* Success/Warning/Error boxes with glow */
        .stSuccess {{
            background: rgba(40, 167, 69, 0.25) !important;
            border: 1px solid rgba(40, 167, 69, 0.7) !important;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 20px rgba(40, 167, 69, 0.3);
            animation: pulseGlow 2s ease-in-out infinite;
        }}

        .stWarning {{
            background: rgba(255, 193, 7, 0.25) !important;
            border: 1px solid rgba(255, 193, 7, 0.7) !important;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 20px rgba(255, 193, 7, 0.3);
        }}

        .stError {{
            background: rgba(220, 53, 69, 0.25) !important;
            border: 1px solid rgba(220, 53, 69, 0.7) !important;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 20px rgba(220, 53, 69, 0.3);
        }}

        @keyframes pulseGlow {{
            0%, 100% {{ box-shadow: 0 4px 20px rgba(40, 167, 69, 0.3); }}
            50% {{ box-shadow: 0 4px 30px rgba(40, 167, 69, 0.6); }}
        }}

        /* Enhanced metrics with hover effect */
        [data-testid="stMetricValue"] {{
            font-size: 2.2rem !important;
            font-weight: 800 !important;
            text-shadow: 2px 2px 8px rgba(0, 0, 0, 0.95);
            color: #ffffff !important;
            transition: transform 0.3s ease;
        }}

        [data-testid="stMetricValue"]:hover {{
            transform: scale(1.1);
        }}

        /* Animated file uploader */
        [data-testid="stFileUploader"] {{
            background: rgba(30, 30, 30, 0.95);
            border-radius: 20px;
            padding: 2.5rem;
            border: 2px dashed rgba(102, 126, 234, 0.5);
            transition: all 0.3s ease;
        }}

        [data-testid="stFileUploader"]:hover {{
            border-color: rgba(102, 126, 234, 0.8);
            background: rgba(40, 40, 40, 0.95);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }}

        /* Sidebar with enhanced styling */
        [data-testid="stSidebar"] {{
            background: rgba(18, 18, 18, 0.98) !important;
            backdrop-filter: blur(15px);
            border-right: 1px solid rgba(102, 126, 234, 0.2);
        }}

        /* Loading spinner enhancement */
        .stSpinner > div {{
            border-top-color: #667eea !important;
            animation: spin 0.8s linear infinite;
        }}

        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}

        /* Info boxes with enhanced styling */
        .stAlert {{
            background: rgba(30, 30, 30, 0.98) !important;
            border-radius: 14px !important;
            border: 1px solid rgba(102, 126, 234, 0.3) !important;
            backdrop-filter: blur(12px);
            animation: fadeIn 0.5s ease;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}

        /* 🎨 Floating particles effect */
        @keyframes float {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-20px); }}
        }}

        /* Download buttons with hover effect */
        .stDownloadButton > button {{
            background: linear-gradient(135deg, #43cea2 0%, #185a9d 100%) !important;
            border: none !important;
            border-radius: 12px !important;
            transition: all 0.3s ease !important;
        }}

        .stDownloadButton > button:hover {{
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(67, 206, 162, 0.5);
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
else:
    # Fallback styling without background image
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #0e1117;
        }
        textarea, input {
            background-color: #1e1e1e !important;
            color: white !important;
            border-radius: 12px !important;
        }
        .stChatMessage {
            background: rgba(30,30,30,0.85);
            border-radius: 14px;
            padding: 12px;
            margin-bottom: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

# ============================================
# REPLACE YOUR ENTIRE SIDEBAR SECTION WITH THIS
# ============================================

with st.sidebar:
    st.title("Contract AI")
    st.caption("Car Deal • Lease • Loan Analyzer")
    
    # Show logged in user
    if 'username' in st.session_state:
        st.success(f"👤 **{st.session_state.username}**")
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    st.markdown("---")
    st.markdown("### Navigation")
    st.markdown("**1️⃣ Upload Contract**")
    st.markdown("**2️⃣ Analyze Deal**")
    st.markdown("**3️⃣ Chat with AI**")
    st.markdown("---")

    if st.button("🆕 New Session (Clear All)", key="sidebar_new_session"):
        st.session_state.chat_history = []
        st.session_state.contracts_context = {}
        st.session_state.active_contract_id = None
        st.rerun()

    st.markdown("---")
    st.markdown("### System Status")
    
    if os.environ.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY"):
        st.success("✅ GROQ_API_KEY loaded")
    else:
        st.error("❌ GROQ_API_KEY not found")
    
    # ✅ FIXED: Show loaded contracts with proper names
    if st.session_state.contracts_context:
        st.markdown("---")
        st.markdown("### 📂 Your Contracts")
        st.caption(f"{len(st.session_state.contracts_context)} contract(s) loaded")
        
        # List each contract
        for cid, ctx in st.session_state.contracts_context.items():
            vehicle = ctx.get('vehicle', {})
            filename = ctx.get('filename', 'Unknown')
            
            # Get vehicle details or use filename
            year = vehicle.get('year', '')
            make = vehicle.get('make', '')
            model = vehicle.get('model', '')
            
            # Create display name
            if year and make and model:
                display_name = f"{year} {make} {model}"
            else:
                # Use filename if no vehicle info
                display_name = filename[:30]  # Truncate long filenames
            
            # Active indicator
            active = "🔵" if cid == st.session_state.active_contract_id else "⚪"
            
            # Contract button
            col1, col2 = st.columns([4, 1])
            
            with col1:
                if st.button(
                    f"{active} {display_name}",
                    key=f"contract_{cid}",
                    use_container_width=True
                ):
                    st.session_state.active_contract_id = cid
                    
                    # Load chat for this contract
                    if 'user_id' in st.session_state:
                        conn = get_connection()
                        cur = conn.cursor()
                        cur.execute("""
                            SELECT role, message, timestamp
                            FROM chat_messages
                            WHERE contract_id = ? AND user_id = ?
                            ORDER BY timestamp ASC
                        """, (cid, st.session_state.user_id))
                        
                        messages = cur.fetchall()
                        st.session_state.chat_history = [
                            {"role": r[0], "content": r[1], "timestamp": r[2]}
                            for r in messages
                        ]
                        conn.close()
                    
                    st.rerun()
            
            with col2:
                # Delete button for each contract
                if st.button("🗑️", key=f"delete_{cid}"):
                    # Delete from database
                    if 'user_id' in st.session_state:
                        conn = get_connection()
                        cur = conn.cursor()
                        
                        # Delete chat messages
                        cur.execute(
                            "DELETE FROM chat_messages WHERE contract_id = ? AND user_id = ?",
                            (cid, st.session_state.user_id)
                        )
                        
                        # Delete contract data
                        cur.execute(
                            "DELETE FROM contract_data WHERE contract_id = ?",
                            (cid,)
                        )
                        
                        # Delete contract
                        cur.execute(
                            "DELETE FROM contracts WHERE id = ? AND user_id = ?",
                            (cid, st.session_state.user_id)
                        )
                        
                        conn.commit()
                        conn.close()
                    
                    # Remove from session
                    del st.session_state.contracts_context[cid]
                    
                    # Clear active contract if it was deleted
                    if st.session_state.active_contract_id == cid:
                        st.session_state.active_contract_id = None
                        st.session_state.chat_history = []
                    
                    st.rerun()
    
    # ✅ FIXED: Chat History section
    if st.session_state.chat_history:
        st.markdown("---")
        st.markdown("### 💬 Chat History")
        
        user_msgs = sum(1 for m in st.session_state.chat_history if m.get("role") == "user")
        ai_msgs = sum(1 for m in st.session_state.chat_history if m.get("role") == "assistant")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Questions", user_msgs)
        with col2:
            st.metric("Responses", ai_msgs)
        
        with st.expander("📜 View History", expanded=False):
            # Show last 10 messages
            recent_msgs = st.session_state.chat_history[-10:] if len(st.session_state.chat_history) > 10 else st.session_state.chat_history
            
            for msg in reversed(recent_msgs):
                role = msg.get("role", "")
                content = msg.get("content", "")
                preview = content[:80] + "..." if len(content) > 80 else content
                
                if role == "user":
                    st.markdown(f"**🧑 You:** {preview}")
                else:
                    st.markdown(f"**🤖 AI:** {preview}")
                st.markdown("---")
        
        # Clear chat button
        if st.button("🗑️ Clear Chat History", key="clear_chat"):
            st.session_state.chat_history = []
            
            # Delete from database
            if st.session_state.active_contract_id and 'user_id' in st.session_state:
                conn = get_connection()
                cur = conn.cursor()
                cur.execute(
                    "DELETE FROM chat_messages WHERE contract_id = ? AND user_id = ?",
                    (st.session_state.active_contract_id, st.session_state.user_id)
                )
                conn.commit()
                conn.close()
            
            st.success("✅ Chat cleared!")
            st.rerun()
# Initialize database
init_db()

# Main title with animation
st.markdown("""
    <div style="animation: titleZoomIn 1s ease-out;">
        <h1 style="text-align: center; margin-bottom: 0;">AI-Powered Car Contract Analyzer</h1>
    </div>
    <style>
        @keyframes titleZoomIn {
            from {
                opacity: 0;
                transform: scale(0.5);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
    </style>
""", unsafe_allow_html=True)

st.markdown('<p style="text-align: center; font-size: 1.1rem; margin-top: 10px; animation: fadeIn 1.5s ease;">Upload your lease or loan agreement to get instant deal analysis and AI-powered insights</p>', unsafe_allow_html=True)

ocr = OCR()
VIN_REGEX = re.compile(r'\b([A-HJ-NPR-Z0-9]{17})\b', re.IGNORECASE)


def find_vin_in_text(text: str):
    if not text:
        return None
    m = VIN_REGEX.search(text)
    return m.group(1).upper() if m else None


def parse_numeric(s):
    """Try to parse numeric money value from string or number; return None if not possible."""
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return float(s)
    if isinstance(s, str):
        s2 = re.sub(r"[^\d\.\-]", "", s)
        try:
            if s2 == "":
                return None
            return float(s2)
        except Exception:
            return None
    return None


def compute_contract_price_from_sla(sla: dict):
    """Best-effort extraction of a contract price from SLA JSON."""
    if not isinstance(sla, dict):
        return (None, None, {"reason": "No SLA dict"})

    loan_keys = ["amount_financed", "loan_principal", "loan_amount", "amount_financed_usd", "principal", "amount"]
    for k in loan_keys:
        if k in sla:
            val = parse_numeric(sla.get(k))
            if val:
                return (val, "loan", {"source_key": k, "raw": sla.get(k)})

    sale_keys = ["sale_price", "total_cash_price", "total_sale_price", "cash_price", "purchase_price"]
    for k in sale_keys:
        if k in sla:
            val = parse_numeric(sla.get(k))
            if val:
                return (val, "sale", {"source_key": k, "raw": sla.get(k)})

    monthly_keys = ["monthly_payment", "monthly", "monthly_payment_amount"]
    term_keys = ["lease_term_duration", "lease_term", "term_months", "loan_term"]
    down_keys = ["down_payment", "downpayment", "cap_cost_reduction"]
    buyout_keys = ["purchase_option_buyout_price", "residual_value", "residual", "buyout"]

    monthly = None
    for k in monthly_keys:
        if k in sla:
            monthly = parse_numeric(sla.get(k))
            if monthly:
                break

    term = None
    for k in term_keys:
        if k in sla:
            term = parse_numeric(sla.get(k))
            break

    down = None
    for k in down_keys:
        if k in sla:
            down = parse_numeric(sla.get(k))
            if down:
                break

    buyout = None
    for k in buyout_keys:
        if k in sla:
            buyout = parse_numeric(sla.get(k))
            if buyout:
                break

    if monthly and term and term > 0:
        total = monthly * term
        if down:
            total += down
        if buyout:
            total += buyout
        return (total, "lease_implied_total", {"monthly": monthly, "term": term, "down": down, "buyout": buyout})

    if monthly:
        return (monthly, "monthly_only", {"monthly": monthly})

    return (None, None, {"reason": "No price-like fields in SLA"})


def choose_market_reference(price_result):
    """Picks best market price from VehicleDatabases or MarketCheck result."""
    if not isinstance(price_result, dict):
        return (None, None, {"reason": "price_result not dict"})

    provider = price_result.get("provider")
    if provider == "vehicledatabases":
        data = price_result.get("data", {})
        summary = price_result.get("summary")
        if summary:
            mr = summary.get("dealer_retail") or summary.get("private_party") or summary.get("trade_in")
            if mr:
                return (mr, "vehicledatabases:dealer_retail", {"summary": summary})
        tv = data.get("trim_values") if isinstance(data, dict) else None
        if tv and isinstance(tv, list) and len(tv) > 0:
            conds = tv[0].get("conditions", {})
            for key in ("Clean", "Outstanding", "Average", "Rough"):
                if key in conds:
                    c = conds[key]
                    mr = c.get("dealer_retail") or c.get("private_party") or c.get("trade_in")
                    if mr:
                        return (mr, f"vehicledatabases:trim:{key}", {"trim": tv[0].get("trim"), "condition": key, "vals": c})
        if tv:
            for entry in tv:
                conds = entry.get("conditions", {})
                for cname, cvals in conds.items():
                    mr = cvals.get("dealer_retail") or cvals.get("private_party") or cvals.get("trade_in")
                    if mr:
                        return (mr, f"vehicledatabases:fallback:{cname}", {"trim": entry.get("trim"), "condition": cname, "vals": cvals})
        return (None, "vehicledatabases", {"reason": "no numeric values found"})

    if provider == "marketcheck":
        data = price_result.get("data") or {}
        if data.get("available"):
            mr = data.get("median") or data.get("p25") or data.get("p75")
            if mr:
                return (mr, "marketcheck:median", {"stats": data})
            else:
                return (None, "marketcheck", {"reason": "no numeric median"})
        else:
            return (None, "marketcheck", {"reason": data.get("reason"), "raw": data.get("raw")})

    if provider == "heuristic":
        d = price_result.get("data") or {}
        mr = d.get("median")
        if mr:
            return (mr, "heuristic:median", {"data": d})
    return (None, None, {"reason": "no provider matched"})


def score_deal(contract_price, market_price):
    """Returns (score_label, color, percent_diff, explanation)"""
    if contract_price is None or market_price is None:
        return (None, "gray", None, "Insufficient data to score deal")

    try:
        pct = (float(contract_price) - float(market_price)) / float(market_price) * 100.0
    except Exception:
        return (None, "gray", None, "Error computing percent diff")

    if pct <= -5.0:
        return ("Great Deal", "green", round(pct, 2), "Contract price is at least 5% below market reference.")
    if -5.0 < pct <= 5.0:
        return ("Fair Deal", "yellow", round(pct, 2), "Contract price is within ±5% of market reference.")
    return ("Bad Deal", "red", round(pct, 2), "Contract price is more than 5% above market reference.")


# ✅ MULTI-CONTRACT AI FUNCTION WITH MEMORY
def ask_contract_ai_multi(user_question: str, contracts_context: dict, active_id: int, chat_history: list = None):
    """
    AI-powered contract assistant supporting multiple contracts for comparison.
    Now includes conversation memory.
    """
    from groq import Groq
    
    api_key = os.environ.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY")
    
    if not api_key:
        return (
            "❌ **GROQ_API_KEY not found!**\n\n"
            "Please add to your `.env` file:\n"
            "```\n"
            "GROQ_API_KEY=gsk_your_key_here\n"
            "```\n"
            "Then restart the Streamlit app."
        )
    
    client = Groq(api_key=api_key)
    
    # Build context from all loaded contracts
    contracts = list(contracts_context.values())
    contract_count = len(contracts)
    
    # Create contract summaries
    contract_summaries = []
    detailed_contexts = []
    
    for idx, ctx in enumerate(contracts, 1):
        vehicle = ctx.get('vehicle', {})
        year = vehicle.get('year', 'Unknown')
        make = vehicle.get('make', 'Unknown')
        model = vehicle.get('model', 'Unknown')
        vin = vehicle.get('vin', 'Not found')
        
        contract_price = ctx.get('contract_price')
        market_price = ctx.get('market_price')
        deal_score = ctx.get('deal_score', 'Not calculated')
        
        contract_price_str = f"${contract_price:,.2f}" if isinstance(contract_price, (int, float)) else "Not available"
        market_price_str = f"${market_price:,.2f}" if isinstance(market_price, (int, float)) else "Not available"
        
        # Summary line
        contract_summaries.append(
            f"Contract #{idx}: {year} {make} {model} | VIN: {vin} | Deal: {deal_score}"
        )
        
        # Detailed context
        sla = ctx.get('sla', {})
        summary = ctx.get('summary', 'No summary available')
        
        detailed_contexts.append(f"""
CONTRACT #{idx} DETAILS:
Vehicle: {year} {make} {model}
VIN: {vin}
Contract Price: {contract_price_str}
Market Reference: {market_price_str}
Deal Score: {deal_score}

Key Fields:
{json.dumps(sla, indent=2)}

Summary:
{summary}
""")
    
    # Build system prompt with multi-contract awareness
    system_prompt = f"""You are Jarvis, an expert automotive contract advisor supporting multi-contract analysis.

NUMBER OF CONTRACTS LOADED: {contract_count}

CONTRACTS OVERVIEW:
{chr(10).join(contract_summaries)}

DETAILED CONTRACT DATA:
{chr(10).join(detailed_contexts)}

RULES:
1. If user asks to compare and only ONE contract exists, respond:
   "Only one contract is currently loaded. Please upload another contract to enable comparisons."

2. If multiple contracts exist:
   - Compare ONLY the contracts provided above
   - Use specific details (prices, terms, VINs) from each contract
   - Point out key differences and similarities
   - Recommend which deal is better and why

3. Never invent or assume vehicles/contracts not provided above

4. If the question is ambiguous, ask for clarification (e.g., "Which contract are you asking about?")

5. Be concise, factual, and actionable

6. Cite specific contract numbers when making comparisons (e.g., "Contract #1 has...")

7. IMPORTANT: Remember the conversation context. If the user corrects you or provides personal info (like their name), acknowledge it and use it in future responses.

8. Maintain a professional but friendly tone as Jarvis, the automotive advisor."""

    # ✅ BUILD CONVERSATION HISTORY FOR API
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add previous conversation turns (last 10 to avoid token limits)
    if chat_history and len(chat_history) > 0:
        recent_history = chat_history[-10:] if len(chat_history) > 10 else chat_history
        for msg in recent_history:
            if msg.get("role") and msg.get("content"):
                messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
    
    # Add current user question
    messages.append({"role": "user", "content": user_question})

    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.4,
            max_tokens=1000,
        )
        
        return completion.choices[0].message.content
        
    except Exception as e:
        return f"⚠️ AI Error: {str(e)}\n\nPlease verify:\n1. GROQ_API_KEY is correct\n2. API has credits/quota\n3. Internet connection is working"


# Upload section
st.markdown("""
    <div style="animation: pulseGently 2s ease-in-out infinite;">
        <h2 style="margin-bottom: 10px;">📄 Upload Your Car Contract</h2>
    </div>
    <style>
        @keyframes pulseGently {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }
    </style>
""", unsafe_allow_html=True)
st.caption("PDF or image of lease / loan agreement")

uploaded_file = st.file_uploader("", type=["png", "jpg", "jpeg", "pdf"], label_visibility="collapsed")

if uploaded_file:
    file_name = uploaded_file.name
    ext = os.path.splitext(file_name)[1].lower()

    if ext in [".png", ".jpg", ".jpeg"]:
        st.image(Image.open(uploaded_file), caption=file_name, use_container_width=True)
    else:
        st.info(f"📄 PDF uploaded: {file_name}")

    if st.button("🚀 Run Full Analysis", type="primary", use_container_width=True, key="run_analysis_button"):
        # 🚀 ROCKET LAUNCH ANIMATION
        
        
        import time
        time.sleep(0.5)  # Brief pause for animation effect
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        try:
            # Save contract to database
            conn = get_connection()
            cur = conn.cursor()
            
            cur.execute(
                "INSERT INTO contracts (filename, created_at) VALUES (?, ?)",
                (file_name, datetime.now().isoformat())
            )
            contract_id = cur.lastrowid
            conn.commit()
            
            # ✅ STEP 2: Set as active contract
            st.session_state.active_contract_id = contract_id

            # 1) OCR
            with st.spinner("🔍 Extracting text from document..."):
                extracted_text = ocr.extract(tmp_path)

            with st.expander("📑 Extracted Contract Text", expanded=False):
                st.text_area("", extracted_text or "[No text extracted]", height=300, label_visibility="collapsed")

            if not extracted_text or not extracted_text.strip():
                st.warning("No text extracted from document.")
                st.stop()

            # 2) Summarize
            with st.spinner("📝 Generating AI summary..."):
                summary = summarize_with_groq(extracted_text)
            
            st.subheader("📋 Contract Summary")
            st.info(summary or "[No summary produced]")
            
            # Store contract in vector DB
            with st.spinner("🔗 Indexing contract for AI chat..."):
                add_document_to_chroma(
                    extracted_text,
                    metadata={"file": file_name, "contract_id": str(contract_id), "summary": summary or ""}
                )

            # 3) SLA extraction
            with st.spinner("⚙️ Extracting contract fields..."):
                sla = extract_sla_with_groq(extracted_text)
            
            with st.expander("📊 Detailed SLA Fields", expanded=False):
                st.json(sla)

            # Save summary & SLA
            cur.execute(
                "INSERT INTO contract_data (contract_id, summary, sla) VALUES (?, ?, ?)",
                (contract_id, summary, json.dumps(sla))
            )
            conn.commit()

            # 4) VIN detection
            vin = None
            if isinstance(sla, dict):
                for k, v in sla.items():
                    if "vin" in k.lower() and isinstance(v, str) and len(v.strip()) == 17:
                        vin = v.strip().upper()
                        break

            if not vin:
                vin = find_vin_in_text(extracted_text)

            if vin:
                st.success(f"✅ VIN found: **{vin}**")

                with st.spinner("🔍 Decoding VIN via NHTSA..."):
                    vin_info = decode_vin_nhtsa(vin)
                
                if vin_info.get("error"):
                    st.error("❌ VIN decode error")
                    with st.expander("VIN Error Details"):
                        st.write(vin_info)
                    vehicle_data = {}
                else:
                    vehicle_data = vin_info.get("data", {})
                    st.success(f"🚗 Vehicle: **{vehicle_data.get('ModelYear')} {vehicle_data.get('Make')} {vehicle_data.get('Model')}**")
                    
                    with st.expander("🔧 Full VIN Decode Data"):
                        st.json(vehicle_data)

                # Extract state and mileage
                state = None
                mileage = None
                if isinstance(sla, dict):
                    for k, v in sla.items():
                        kl = k.lower()
                        if "state" in kl and isinstance(v, str) and len(v.strip()) > 0:
                            state = v.strip()
                        if "mileage" in kl or "miles" in kl:
                            if isinstance(v, (int, float)):
                                mileage = int(v)
                            elif isinstance(v, str):
                                digits = re.sub(r"[^\d]", "", v)
                                if digits:
                                    try:
                                        mileage = int(digits)
                                    except Exception:
                                        pass

                st.markdown("---")
                st.subheader("🎯 Vehicle Context (Optional)")
                st.caption("Improves pricing accuracy")
                
                col1, col2 = st.columns(2)
                with col1:
                    user_state = st.text_input("State (e.g. PA)", value=(state or ""), placeholder="CA")
                with col2:
                    user_mileage = st.text_input("Mileage", value=(str(mileage) if mileage else ""), placeholder="25000")

                if user_state:
                    state = user_state.strip()
                if user_mileage:
                    digits = re.sub(r"[^\d]", "", user_mileage)
                    if digits:
                        mileage = int(digits)

                # 5) Price estimation
                st.markdown("---")
                with st.spinner("💰 Fetching market prices..."):
                    make = vehicle_data.get("Make", "")
                    model = vehicle_data.get("Model", "")
                    year = vehicle_data.get("ModelYear", "")
                    price_result = estimate_price(
                        make=make, 
                        model=model, 
                        year=year, 
                        body_class=vehicle_data.get("BodyClass", ""), 
                        vin=vin, 
                        state=state, 
                        mileage=mileage, 
                        zip_code="94103", 
                        env=dict(os.environ)
                    )

                st.subheader("💵 Market Analysis")
                provider = price_result.get("provider")
                st.caption(f"Data source: {provider}")

                market_price, market_ref_source, market_detail = choose_market_reference(price_result)

                if market_price:
                    st.metric("Market Reference Price", f"${market_price:,.0f}", help=market_ref_source)
                else:
                    st.warning("⚠️ No market numeric reference available")
                    if market_detail and market_detail.get("reason"):
                        st.caption(f"Reason: {market_detail.get('reason')}")

                contract_price, contract_type, contract_expl = compute_contract_price_from_sla(sla)
                if contract_price:
                    st.metric("Contract Price", f"${contract_price:,.0f}", help=f"Source: {contract_type}")
                else:
                    st.warning("⚠️ Could not extract contract price")
                    st.caption(f"Reason: {contract_expl.get('reason')}")

                # Deal score
                st.markdown("---")
                st.subheader("🎯 Deal Score")
                
                score_label, color, pct_diff, explanation = score_deal(contract_price, market_price)
                if score_label:
                    if color == "green":
                        st.success(f"### {score_label}")
                        st.write(f"**{pct_diff}%** vs market")
                        st.write(explanation)
                    elif color == "yellow":
                        st.warning(f"### {score_label}")
                        st.write(f"**{pct_diff}%** vs market")
                        st.write(explanation)
                    elif color == "red":
                        st.error(f"### {score_label}")
                        st.write(f"**{pct_diff}%** vs market")
                        st.write(explanation)
                    else:
                        st.info(f"### {score_label}")
                        st.write(explanation)
                else:
                    st.info("Deal Score: Not available — insufficient data")
                    
                # Monthly Lease Parity
                st.markdown("---")
                st.subheader("📊 Monthly Lease Parity")

                lease_term = None
                if isinstance(sla, dict):
                    for k in ["lease_term_duration", "lease_term", "term_months"]:
                        if k in sla:
                            try:
                                lease_term = int(float(str(sla[k]).split()[0]))
                                break
                            except:
                                pass

                contract_monthly = None
                if isinstance(sla, dict):
                    for k in ["monthly_payment", "monthly"]:
                        if k in sla:
                            try:
                                contract_monthly = float(
                                    str(sla[k]).replace("$", "").replace(",", "")
                                )
                                break
                            except:
                                pass

                if market_price and lease_term:
                    market_monthly = calculate_market_monthly_lease(
                        dealer_retail_price=market_price,
                        lease_term_months=lease_term
                    )

                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Market Monthly", f"${market_monthly:.0f}")
                    with col2:
                        if contract_monthly:
                            st.metric("Contract Monthly", f"${contract_monthly:.0f}")

                    if contract_monthly:
                        diff = round(contract_monthly - market_monthly, 2)

                        if diff <= -10:
                            st.success(f"🟢 Excellent lease — ${abs(diff):.0f} cheaper than market/month")
                        elif -10 < diff <= 10:
                            st.warning(f"🟡 Fair lease — within ±$10 of market/month")
                        else:
                            st.error(f"🔴 Overpriced lease — ${diff:.0f} higher than market/month")
                    else:
                        st.info("Monthly payment not found in SLA.")
                else:
                    st.info("Lease parity not applicable (missing lease term or market price).")

                # Recommendations
                if contract_price and market_price:
                    diff = round(contract_price - market_price, 2)
                    st.markdown("---")
                    st.subheader("💡 Recommendation")
                    if color == "green":
                        st.success(f"This looks like a **good deal**. Contract price is ${abs(diff):,.0f} below market ({market_ref_source}). Consider proceeding.")
                    elif color == "yellow":
                        st.info(f"This is a **fair deal** (within ±5%). You may negotiate fees. Difference: ${diff:,.0f}.")
                    elif color == "red":
                        st.warning(f"Contract price is **higher than market** by ${diff:,.0f}. Recommend negotiating before acceptance.")
                else:
                    st.info("Insufficient data for recommendations.")

                # Provider details in expanders
                with st.expander("📊 Pricing Details", expanded=False):
                    if provider == "vehicledatabases":
                        data = price_result.get("data") or {}
                        summary_data = price_result.get("summary")
                        if summary_data:
                            st.write("**VehicleDatabases Summary:**")
                            st.json(summary_data)
                        tv = data.get("trim_values") or []
                        if tv:
                            st.write("**Trim/Condition Details:**")
                            for entry in tv:
                                trim = entry.get("trim") or "Trim"
                                st.markdown(f"**{trim}**")
                                conds = entry.get("conditions") or {}
                                for cname, cvals in conds.items():
                                    st.write(f"- {cname}: trade_in={cvals.get('trade_in')}, private_party={cvals.get('private_party')}, dealer_retail={cvals.get('dealer_retail')}")
                    elif provider == "marketcheck":
                        st.json(price_result.get("data", {}))
                    else:
                        st.json(price_result.get("data", {}))

                # Downloads
                st.markdown("---")
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        "📄 Download Text", 
                        data=extracted_text, 
                        file_name=f"{os.path.splitext(file_name)[0]}_extracted.txt",
                        use_container_width=True,
                        key=f"download_text_{contract_id}"
                    )
                with col2:
                    st.download_button(
                        "📊 Download SLA JSON", 
                        data=json.dumps(sla, indent=2), 
                        file_name=f"{os.path.splitext(file_name)[0]}_sla.json",
                        use_container_width=True,
                        key=f"download_sla_{contract_id}"
                    )

                # ✅ STEP 1: Store in multi-contract context
                st.session_state.contracts_context[contract_id] = {
                    "filename": file_name,
                    "summary": summary,
                    "sla": sla,
                    "vehicle": {
                        "vin": vin,
                        "make": vehicle_data.get("Make"),
                        "model": vehicle_data.get("Model"),
                        "year": vehicle_data.get("ModelYear"),
                    },
                    "market_price": market_price,
                    "contract_price": contract_price,
                    "deal_score": score_label
                }

            else:
                st.warning("⚠️ No VIN detected")
                st.info("Enter VIN manually or ensure contract contains the VIN.")
                manual = st.text_input("Manual VIN (17 characters)")
                if manual and len(manual.strip()) == 17:
                    st.success("✅ Manual VIN entered — re-run to fetch price.")

        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

else:
    st.info("👆 Please upload a PDF or image to start")
    
    # Add instructions
    with st.expander("ℹ️ How to Use This Tool", expanded=True):
        st.markdown("""
        ### Steps:
        1. **Upload** your car lease contract (PDF or image)
        2. **Review** the extracted text and contract terms
        3. **Analyze** the VIN and market pricing data
        4. **Compare** multiple contracts (upload more)
        5. **Chat** with AI for insights and comparisons
        
        ### What You'll Get:
        - ✅ Automatic text extraction (OCR)
        - ✅ Contract terms identification
        - ✅ Vehicle information from VIN
        - ✅ Real-time market pricing
        - ✅ Multi-contract comparison
        - ✅ AI negotiation assistance
        
        ### Tips:
        - Upload multiple contracts to compare deals
        - Ensure contracts are clearly readable
        - VIN must be visible in the document
        - Ask the AI to compare contracts directly
        """)


# ✅ STEP 5: Multi-contract aware chat UI
if st.session_state.contracts_context:
    st.markdown("---")
    st.markdown("## 💬 Contract Q&A Assistant")
    
    # ✅ User-friendly contract counter
    contract_count = len(st.session_state.contracts_context)
    if contract_count == 1:
        st.info(
            f"📂 **{contract_count} contract** loaded. Upload another contract to enable comparisons."
        )
    else:
        st.success(
            f"📂 **{contract_count} contracts** loaded. Ask me to compare them!"
        )
    
    st.caption("Ask about APR, payments, penalties, risks, negotiation tips, or compare contracts")

    # Render full chat history
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Handle user input
    user_question = st.chat_input("Type your question and press Enter...")

    if user_question:
        # Database operations
        conn = get_connection()
        cur = conn.cursor()
        contract_id = st.session_state.active_contract_id
        
        # Save user message to session
        st.session_state.chat_history.append(
            {"role": "user", "content": user_question}
        )
        
        # Save to database
        if contract_id:
            cur.execute(
                "INSERT INTO chat_messages (contract_id, role, message, timestamp) VALUES (?, ?, ?, ?)",
                (contract_id, "user", user_question, datetime.now().isoformat())
            )
            conn.commit()

        # Display user message
        with st.chat_message("user"):
            st.markdown(user_question)

        # Generate and display AI reply using multi-contract function
        with st.chat_message("assistant"):
            with st.spinner("🤔 Thinking..."):
                try:
                    # ✅ SAFE: Pass chat history as keyword argument
                    assistant_reply = ask_contract_ai_multi(
                        user_question=user_question,
                        contracts_context=st.session_state.contracts_context,
                        active_id=st.session_state.active_contract_id,
                        chat_history=st.session_state.chat_history
                    )
                except Exception as e:
                    assistant_reply = f"⚠️ AI Error: {str(e)}\n\nDebug info: {type(e).__name__}"

            st.markdown(assistant_reply)

        # Save AI reply to session
        st.session_state.chat_history.append(
            {"role": "assistant", "content": assistant_reply}
        )
        
        # Save to database
        if contract_id:
            cur.execute(
         "INSERT INTO chat_messages (contract_id, user_id, role, message, timestamp) VALUES (?, ?, ?, ?, ?)",
             (contract_id, st.session_state.user_id, "user", user_question, datetime.now().isoformat())
                )

            conn.commit()