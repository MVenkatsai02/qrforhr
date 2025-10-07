import streamlit as st
import pandas as pd
import bcrypt
import sqlite3
import os
import io
from datetime import datetime
from pytz import timezone
from PIL import Image
from cryptography.fernet import Fernet
from geopy.distance import geodesic
from streamlit_geolocation import streamlit_geolocation
import qrcode

# ---------- CONFIG ----------
IST = timezone("Asia/Kolkata")
OFFICE_LAT, OFFICE_LON = 17.434059257137925, 78.37883225744869
MAX_DISTANCE_KM = 0.1

DB_FILE = "attendance.db"
SECURE_DIR = "secure_data"
QR_DIR = "qrcodes"
LOG_DIR = "logs"

os.makedirs(SECURE_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Load secrets
HR_PASSWORD_HASH = os.getenv("HR_PASSWORD_HASH", st.secrets.get("HR_PASSWORD_HASH"))
FERNET_KEY = os.getenv("ENCRYPTION_KEY", st.secrets.get("ENCRYPTION_KEY"))
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id TEXT,
            name TEXT,
            date TEXT,
            login_time TEXT,
            logout_time TEXT,
            hours_worked REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def record_login(emp_id, name, date):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    login_time = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO attendance (emp_id, name, date, login_time) VALUES (?, ?, ?, ?)",
              (emp_id, name, date, login_time))
    conn.commit()
    conn.close()
    return login_time

def record_logout(emp_id, date):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    logout_time = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT login_time FROM attendance WHERE emp_id=? AND date=?", (emp_id, date))
    login_time = c.fetchone()[0]
    login_dt = datetime.strptime(login_time, "%Y-%m-%d %H:%M:%S")
    logout_dt = datetime.strptime(logout_time, "%Y-%m-%d %H:%M:%S")
    hours = round((logout_dt - login_dt).total_seconds() / 3600, 2)
    c.execute("UPDATE attendance SET logout_time=?, hours_worked=? WHERE emp_id=? AND date=?",
              (logout_time, hours, emp_id, date))
    conn.commit()
    conn.close()
    return logout_time, hours

def get_today_records():
    conn = sqlite3.connect(DB_FILE)
    today = datetime.now(IST).strftime("%Y-%m-%d")
    df = pd.read_sql(f"SELECT * FROM attendance WHERE date='{today}'", conn)
    conn.close()
    return df

def get_records_by_date(date):
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql(f"SELECT * FROM attendance WHERE date='{date}'", conn)
    conn.close()
    return df

def get_employee_history(emp_id):
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql(f"SELECT * FROM attendance WHERE emp_id='{emp_id}' ORDER BY date DESC", conn)
    conn.close()
    return df

# ---------- LOCATION ----------
def get_user_location():
    st.write("📍 Click below to share your location")
    location = streamlit_geolocation()
    if location and "latitude" in location:
        lat, lon = location["latitude"], location["longitude"]
        st.success(f"✅ Location captured ({lat:.5f}, {lon:.5f})")
        return lat, lon
    st.info("Please allow location access.")
    return None

def within_office(lat, lon, radius_km=MAX_DISTANCE_KM):
    dist = geodesic((lat, lon), (OFFICE_LAT, OFFICE_LON)).km
    return dist <= radius_km, round(dist, 3)

# ---------- EMPLOYEE FILE HANDLING ----------
EMP_FILE_PATH = os.path.join(SECURE_DIR, "employees.enc")

def encrypt_and_save(df):
    data_bytes = df.to_csv(index=False).encode()
    encrypted = fernet.encrypt(data_bytes)
    with open(EMP_FILE_PATH, "wb") as f:
        f.write(encrypted)

def decrypt_and_load():
    if not os.path.exists(EMP_FILE_PATH):
        return None
    with open(EMP_FILE_PATH, "rb") as f:
        decrypted = fernet.decrypt(f.read()).decode()
    return pd.read_csv(io.StringIO(decrypted))

# ---------- QR GENERATION ----------
def generate_qr():
    today = datetime.now(IST).strftime("%Y-%m-%d")
    qr_path = os.path.join(QR_DIR, f"qr_{today}.png")
    base_url = st.secrets.get("BASE_URL", "https://qrforhr.streamlit.app/")
    qr = qrcode.make(f"{base_url}?date={today}")
    qr.save(qr_path)
    return qr_path

# ---------- UI START ----------
st.set_page_config(page_title="QR Attendance System", page_icon="📌")

# Header with logo
col1, col2 = st.columns([1, 5])
with col1:
    st.image("logo.png", width=70)
with col2:
    st.markdown("### **TW**")

st.title("📌 QR Attendance System with Location Validation (IST)")

role = st.sidebar.radio("Select Mode", ["Employee", "HR/Admin", "QR Display"])

# ---------- EMPLOYEE MODE ----------
if role == "Employee":
    st.subheader("Employee Attendance Portal")

    emp_id = st.text_input("Employee ID")
    name = st.text_input("Name")
    password = st.text_input("Password", type="password")

    df = decrypt_and_load()

    if df is None:
        st.error("⚠️ Employee database not uploaded by HR yet.")
    elif emp_id and name and password:
        user = df[(df["emp_id"] == emp_id) & (df["name"] == name)]
        if user.empty:
            st.error("❌ Invalid credentials.")
        else:
            hashed_pw = user.iloc[0]["password"].encode()
            if bcrypt.checkpw(password.encode(), hashed_pw):
                location = get_user_location()
                if location:
                    lat, lon = location
                    is_inside, dist = within_office(lat, lon)
                    if not is_inside:
                        st.error(f"❌ You are {dist*1000:.1f} m away from office.")
                    else:
                        st.success("✅ Inside office premises.")
                        today = datetime.now(IST).strftime("%Y-%m-%d")
                        conn = sqlite3.connect(DB_FILE)
                        c = conn.cursor()
                        c.execute("SELECT * FROM attendance WHERE emp_id=? AND date=?", (emp_id, today))
                        record = c.fetchone()
                        conn.close()
                        if not record:
                            login = record_login(emp_id, name, today)
                            st.success(f"🕒 Login recorded at {login}")
                        elif record[5] is None:
                            logout, hrs = record_logout(emp_id, today)
                            st.success(f"🕒 Logout recorded at {logout} | Worked {hrs} hrs")
                        else:
                            st.warning("⚠️ You already logged out today.")

                        hist = get_employee_history(emp_id)
                        if not hist.empty:
                            st.write("### Your Last 7 Days Attendance")
                            st.dataframe(hist.head(7)[["date", "login_time", "logout_time", "hours_worked"]])
            else:
                st.error("❌ Wrong password.")

# ---------- HR / ADMIN MODE ----------
elif role == "HR/Admin":
    st.subheader("HR Dashboard")
    pw = st.text_input("Enter HR Password", type="password")

    if pw and bcrypt.checkpw(pw.encode(), HR_PASSWORD_HASH.encode()):
        tabs = st.tabs(["📅 Attendance Overview", "🔍 Employee Search", "📁 Upload Employee File", "⚙️ System Controls"])

        # --- Tab 1: Calendar Attendance ---
        with tabs[0]:
            date_sel = st.date_input("Select Date", datetime.now(IST).date())
            df = get_records_by_date(date_sel.strftime("%Y-%m-%d"))
            if df.empty:
                st.info("No records for this date.")
            else:
                st.dataframe(df)
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("📤 Download CSV", csv, f"attendance_{date_sel}.csv")

        # --- Tab 2: Employee Search ---
        with tabs[1]:
            df = decrypt_and_load()
            if df is None:
                st.warning("Upload employee file first.")
            else:
                query = st.text_input("Search Employee (name or ID)")
                if query:
                    matches = df[df["name"].str.contains(query, case=False) | df["emp_id"].astype(str).str.contains(query)]
                    for _, row in matches.iterrows():
                        if st.button(f"{row['emp_id']} - {row['name']}"):
                            hist = get_employee_history(row["emp_id"])
                            st.dataframe(hist)

        # --- Tab 3: Upload Employee File ---
        with tabs[2]:
            st.write("Upload new employee Excel (columns: emp_id, name, department, role, password)")
            file = st.file_uploader("Choose File", type=["xlsx", "csv"])
            if file:
                df = pd.read_excel(file) if file.name.endswith("xlsx") else pd.read_csv(file)
                df["password"] = df["password"].apply(lambda x: bcrypt.hashpw(str(x).encode(), bcrypt.gensalt()).decode())
                encrypt_and_save(df)
                st.success("✅ Employee file uploaded & encrypted successfully.")

        # --- Tab 4: System Controls ---
        with tabs[3]:
            if st.button("Generate New QR"):
                qr_path = generate_qr()
                st.image(qr_path, caption="Today's QR", width=200)
            if os.path.exists(os.path.join(LOG_DIR, "hr_audit.txt")):
                with open(os.path.join(LOG_DIR, "hr_audit.txt")) as f:
                    st.text(f.read())

    elif pw:
        st.error("Invalid HR password")

# ---------- QR DISPLAY MODE ----------
else:
    st.subheader("QR Display Mode")
    qr_path = generate_qr()
    st.image(qr_path, caption="Today's Attendance QR", width=300)
    st.info("Employees can scan this QR to open the app and mark attendance.")
