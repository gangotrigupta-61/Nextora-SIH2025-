import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from urllib.parse import urljoin
from dotenv import load_dotenv

# Generate a random key if not found in .env
secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(32)  # generates a secure random key
    print(f"[INFO] Generated secret key: {secret_key}")  # shows in terminal

# --- Gemini AI ---
import google.generativeai as genai

# Load .env values
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_change_me")
oauth = OAuth(app)

# ---- MySQL Config ----
mydb = mysql.connector.connect(
    host=os.environ.get("DB_HOST"),
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASSWORD"),
    database=os.environ.get("DB_NAME"),
    port=int(os.environ.get("DB_PORT"))
)

# ---- Google OAuth Config ----
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

def _abs_url(endpoint):
    return urljoin(request.url_root, url_for(endpoint))

# ---- Gemini Setup ----
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# ---- Routes ----
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/auth", methods=["GET","POST"])
def auth():
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form["email"].lower()
        password = request.form["password"]

        cursor = mydb.cursor(dictionary=True)

        if action == "signup":
            # Check if already registered
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            if cursor.fetchone():
                flash("Email already registered. Please login.")
                cursor.close()
                return redirect(url_for("auth"))

            # Collect extra fields
            first_name = request.form["first_name"]
            last_name = request.form["last_name"]
            state = request.form["state"]
            city = request.form["city"]
            phone = request.form["phone"]
            # Checkbox: enrolled = True by default, False if ticked
            enrolled = not bool(request.form.get("not_enrolled"))

            hashed_pw = generate_password_hash(password)

            cursor.execute("""
                INSERT INTO users 
                (first_name, last_name, state, city, phone, email, password, auth_provider, enrolled) 
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (first_name, last_name, state, city, phone, email, hashed_pw, "password", enrolled))
            mydb.commit()
            cursor.close()

            flash("Signup successful. Please login!")
            return redirect(url_for("auth"))

        elif action == "login":
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
            cursor.close()
            if user and user["password"] and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                session["email"] = user["email"]
                session["name"] = user.get("first_name", "") + " " + user.get("last_name", "")
                flash("Login successful!")
                return redirect(url_for("home"))
            else:
                flash("Invalid login credentials.")
                return redirect(url_for("auth"))

    return render_template("auth.html")

@app.route("/login/google")
def login_google():
    redirect_uri = os.getenv("OAUTH_REDIRECT_URI", _abs_url("auth_google_callback"))
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    token = google.authorize_access_token()
    resp = google.get("userinfo")
    info = resp.json()
    email = info.get("email")

    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    # ✅ Allow only if user already signed up earlier
    if not user:
        flash("You must sign up first using email/password before using Google login.")
        cursor.close()
        return redirect(url_for("auth"))

    cursor.close()
    session["user_id"] = user["id"]
    session["email"] = email
    session["name"] = (user.get("first_name") or "") + " " + (user.get("last_name") or "")
    flash("Signed in with Google!")
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    # ensure user logged in
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("auth"))

    user_id = session["user_id"]
    cursor = mydb.cursor(dictionary=True)

    if request.method == "POST":
        # read form values
        first_name = request.form.get("first_name", "").strip()
        last_name  = request.form.get("last_name", "").strip()
        state      = request.form.get("state", "").strip()
        city       = request.form.get("city", "").strip()
        phone      = request.form.get("phone", "").strip()
        # checkbox named "not_enrolled": if present and equals '1' -> NOT enrolled
        not_enrolled = request.form.get("not_enrolled") == "1"
        enrolled = not not_enrolled

        # update DB
        update_q = """
            UPDATE users
            SET first_name=%s, last_name=%s, state=%s, city=%s, phone=%s, enrolled=%s
            WHERE id=%s
        """
        cursor.execute(update_q, (first_name, last_name, state, city, phone, enrolled, user_id))
        mydb.commit()
        flash("Profile updated successfully!")

    # fetch user record (select only needed columns)
    cursor.execute("""
        SELECT id, first_name, last_name, state, city, phone, email, enrolled
        FROM users WHERE id=%s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()

    # Render template with user dict (values can be None if not set)
    return render_template("profile.html", user=user)


@app.route("/home")
def home():
    if "user_id" not in session:
        return redirect(url_for("auth"))
    return render_template("home.html", name=session.get("name"), email=session.get("email"))

@app.route("/intro")
def intro():
    return render_template("intro.html")

@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html")

@app.route("/guidance")
def guidance():
    return render_template("guidance.html")


@app.route("/notification")
def notification():
    return render_template("notification.html")

@app.route("/aptitude")
def aptitude():
    return render_template("aptitude.html")

@app.route("/gap", methods=["GET", "POST"])
def gap():
    result = None
    if request.method == "POST":
        if "reset" in request.form:
            return render_template("gap.html")  # clear form

        elif "analyse" in request.form:
            skills = request.form.get("skills", "").lower()
            career = request.form.get("career", "").lower()

            # Simple hardcoded requirements
            career_requirements = {
                "data scientist": ["python", "statistics", "machine learning", "sql"],
                "web developer": ["html", "css", "javascript", "react"],
                "android developer": ["java", "kotlin", "android sdk"],
                "ui/ux designer": ["figma", "wireframing", "prototyping"]
            }

            required = career_requirements.get(career, [])
            user_skills = [s.strip() for s in skills.split(",") if s.strip()]

            missing = [skill for skill in required if skill not in user_skills]

            if required:
                result = (
                    f"✅ Target Career: {career.title()}\n\n"
                    f"Your Skills: {', '.join(user_skills) if user_skills else 'None'}\n"
                    f"Required Skills: {', '.join(required)}\n\n"
                    f"❌ Missing Skills: {', '.join(missing) if missing else 'None'}"
                )
            else:
                result = f"No predefined requirements found for career '{career}'."

    return render_template("gap.html", result=result)


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/help")
def help():
    return render_template("help.html")

@app.route("/college")
def college():
    return render_template("college.html")

@app.route("/resume")
def resume():
    return render_template("resume.html")

@app.route("/interview")
def interview():
    return render_template("interview.html")


@app.route("/mentor")
def mentor():
    return render_template("mentor.html")


@app.route("/FAQs")
def FAQs():
    return render_template("FAQs.html")

# ---- Gemini Chat API Route ----
@app.route("/ask_gemini", methods=["POST"])
def ask_gemini():
    user_input = request.json.get("message", "")
    if not user_input:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        response = model.generate_content(user_input)
        return jsonify({"reply": response.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
