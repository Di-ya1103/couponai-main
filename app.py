from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, make_response
from flask_restful import Api, Resource, reqparse
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity, get_jwt
import mysql.connector
from entity_extraction.rules import EnhancedRuleBasedExtractor
import logging
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta
import re
from markupsafe import Markup
from typing import Optional, Dict

# Configure Flask app to serve static files from coupon_data directory
app = Flask(__name__, static_folder='coupon_data', static_url_path='/coupon_data')
app.secret_key = os.urandom(24)
load_dotenv()

# JWT_SECRET_KEY configuration
jwt_secret_key = os.getenv('JWT_SECRET_KEY')
if not jwt_secret_key:
    raise ValueError('JWT_SECRET_KEY not set in .env')
app.config['JWT_SECRET_KEY'] = jwt_secret_key

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)
api = Api(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)

def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=os.getenv("DB_PORT", "3306"),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", "root"),
                database=os.getenv("DB_NAME", "coupon"),
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci',
                autocommit=True
            )
            logging.info("Connected to database")
        except mysql.connector.Error as e:
            logging.error(f"Database connection error: {e}")
            raise Exception("Failed to connect to database")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None and db.is_connected():
        db.close()
        logging.info("Database connection closed")

class User(UserMixin):
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
        user = cursor.fetchone()
        if user:
            return User(id=user['id'], name=user['name'], email=user['email'])
    finally:
        cursor.close()
    return None

@jwt.token_verification_loader
def check_token_validity(jwt_header, jwt_payload):
    token = get_jwt()['jti']
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT revoked, expires_at FROM api_tokens WHERE token = %s", (token,))
        token_data = cursor.fetchone()
        if not token_data or token_data['revoked'] == 1 or token_data['expires_at'] < datetime.utcnow():
            return False
        return True
    except mysql.connector.Error as e:
        logging.error(f"Token verification error: {e}")
        return False
    finally:
        cursor.close()

def _format_discount(discount: Optional[Dict]) -> str:
    if not discount:
        return "Any"
    if discount['min'] == 0:
        return f"Up to {discount['max']}%"
    elif discount['max'] == 100:
        return f"At least {discount['min']}%"
    else:
        return f"{discount['min']}% to {discount['max']}%"

def _get_area_from_location(location: Optional[Dict]) -> str:
    if not location or not isinstance(location, dict):
        return "Any"
    location_type = location.get('type')
    location_table = location.get('table')
    if location_type == 'area':
        return location.get('name', 'Any')
    elif location_type == 'selected_area' and location_table:
        area_map = {
            'hong_kong': 'Hong Kong',
            'kowloon': 'Kowloon',
            'new_territories': 'New Territories'
        }
        return area_map.get(location_table, 'Any')
    return "Any"

def _get_coupon_area_name(db, area_id: str) -> str:
    if not area_id:
        logging.debug("No area_id provided, returning 'Any'")
        return "Any"

    area_id = str(area_id)
    logging.debug(f"Attempting to resolve area_id: {area_id}")

    area_map = {
        '2': 'Kowloon',
        '1': 'Hong Kong',
        '3': 'New Territories'
    }

    if area_id in area_map:
        logging.debug(f"Resolved area_id {area_id} to {area_map[area_id]} via area_map")
        return area_map[area_id]

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT name_en FROM area WHERE id = %s AND status = 1 AND deleted_at IS NULL", (area_id,))
        row = cursor.fetchone()
        if row:
            area_name = row['name_en']
            logging.debug(f"Resolved area_id {area_id} to {area_name} via area table")
            return area_name

        cursor.execute("SELECT merchant_city FROM users WHERE merchant_city = %s LIMIT 1", (area_id,))
        row = cursor.fetchone()
        if row:
            area_name = row['merchant_city']
            logging.debug(f"Resolved area_id {area_id} to {area_name} via users.merchant_city")
            return area_name

        extractor = EnhancedRuleBasedExtractor(db)
        area_data = extractor.area_data
        if area_id in area_data:
            area_name = area_data[area_id]['name_en']
            logging.debug(f"Resolved area_id {area_id} to {area_name} via area_data")
            return area_name

        logging.warning(f"Could not resolve area_id {area_id}. Returning 'Any'")
        return "Any"
    except mysql.connector.Error as e:
        logging.error(f"Error fetching area name for area_id {area_id}: {e}")
        return "Any"
    finally:
        cursor.close()

def _get_area_name(db, selected_area: str, territory: str, location_table: str = None, coupon_area: str = None) -> Optional[str]:
    if not selected_area:
        logging.debug("No selected_area provided, returning 'Any'")
        return "Any"

    selected_area = str(selected_area)
    logging.debug(f"Attempting to resolve selected_area: {selected_area}, territory: {territory}, location_table: {location_table}, coupon_area: {coupon_area}")

    territory = territory.lower().replace(' ', '_') if territory else None
    location_tables = {
        'kowloon': 'kowloon',
        'hong_kong': 'hong_kong',
        'new_territories': 'new_territories',
        'hk': 'hong_kong',
        'hong kong': 'hong_kong',
        'new territories': 'new_territories'
    }

    area_to_table = {
        '2': 'kowloon',
        '1': 'hong_kong',
        '3': 'new_territories'
    }

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT name_en FROM area WHERE id = %s AND status = 1 AND deleted_at IS NULL", (selected_area,))
        row = cursor.fetchone()
        if row:
            area_name = row['name_en']
            logging.debug(f"Resolved selected_area {selected_area} to {area_name} via area table")
            return area_name

        tables_to_try = []
        if location_table:
            tables_to_try.append(location_table)
        if territory and territory in location_tables:
            tables_to_try.append(location_tables[territory])
        if coupon_area and coupon_area in area_to_table:
            tables_to_try.append(area_to_table[coupon_area])
        tables_to_try.extend([t for t in ['hong_kong', 'kowloon', 'new_territories'] if t not in tables_to_try])

        for table in tables_to_try:
            query = f"SELECT name_en FROM {table} WHERE id = %s AND status = 1 AND deleted_at IS NULL"
            cursor.execute(query, (selected_area,))
            row = cursor.fetchone()
            if row:
                if coupon_area and table != area_to_table.get(coupon_area):
                    logging.warning(f"Selected_area '{selected_area}' found in {table}, but coupon_area '{coupon_area}' expects {area_to_table.get(coupon_area)}")
                    continue
                area_name = row['name_en']
                logging.debug(f"Resolved selected_area {selected_area} to {area_name} via {table} table")
                return area_name

        extractor = EnhancedRuleBasedExtractor(db)
        location_data = extractor.location_data
        for table in tables_to_try:
            if table in location_data and selected_area in location_data[table]:
                if coupon_area and table != area_to_table.get(coupon_area):
                    logging.warning(f"Selected_area '{selected_area}' found in {table}, but coupon_area '{coupon_area}' expects {area_to_table.get(coupon_area)}")
                    continue
                area_name = location_data[table][selected_area]['name_en']
                logging.debug(f"Resolved selected_area {selected_area} to {area_name} via location_data[{table}]")
                return area_name

        cursor.execute("SELECT selected_area FROM users WHERE selected_area = %s LIMIT 1", (selected_area,))
        row = cursor.fetchone()
        if row:
            area_name = row['selected_area']
            logging.debug(f"Resolved selected_area {selected_area} to {area_name} via users.selected_area")
            return area_name

        logging.warning(f"No area name found for selected_area: {selected_area} in tables: {tables_to_try}. Returning 'Any'.")
        return "Any"
    except mysql.connector.Error as e:
        logging.error(f"Error fetching area name for selected_area {selected_area}, territory {territory}: {e}")
        return "Any"
    finally:
        cursor.close()

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if 'queries' not in session:
        session['queries'] = []
    if 'messages' not in session:
        session['messages'] = []
    if 'context' not in session:
        session['context'] = {'category': None, 'location': None, 'discount': None, 'coupon_name': None}

    error = None
    coupons = []
    query = None
    db = get_db()
    extractor = EnhancedRuleBasedExtractor(db)

    if request.method == 'POST':
        action = request.form.get('action')
        query = request.form.get('query', '').strip().lower()

        if action == 'quit' or query == 'quit':
            user_id = current_user.id
            db = get_db()
            cursor = db.cursor()
            try:
                cursor.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = %s AND revoked = 0", (user_id,))
                logging.info(f"Revoked tokens for user ID {user_id} during quit")
            except mysql.connector.Error as e:
                logging.error(f"Token revocation error during quit: {e}")
            finally:
                cursor.close()
            logout_user()
            flash('Logged out successfully. See you soon! 😎', 'success')
            return redirect(url_for('login'))

        if action == 'clear':
            # Preserve Flask-Login session data by not clearing the entire session
            session.pop('messages', None)
            session.pop('queries', None)
            session.pop('context', None)
            session.pop('latest_query', None)
            session['messages'] = [{'type': 'system', 'content': 'Poof! History cleared. Let’s start fresh! 🚀'}]
            session['queries'] = []
            session['context'] = {'category': None, 'location': None, 'discount': None, 'coupon_name': None}
            session['latest_query'] = None
            logging.debug("Chatbot session data cleared via 'clear' action. Reloading index page.")
            session.modified = True
            return redirect(url_for('index'))

        if not query:
            error = "Hey, you gotta tell me what you’re looking for! 😅"
            session['messages'].append({'type': 'system', 'content': error})
        else:
            if session.get('latest_query') != query:
                session['messages'] = []
                logging.debug(f"Cleared session messages. Starting fresh for query: {query}")
                session['latest_query'] = query
            else:
                logging.debug(f"Same query as last time: {query}. Keeping existing messages.")
            
            session['messages'].append({'type': 'user', 'content': query})

            try:
                current_category = extractor.extract_category(query)
                current_location = extractor._extract_location_from_query(query)
                current_discount = extractor._extract_discount_from_query(query)
                current_coupon_name = extractor._extract_coupon_name_from_query(query)

                logging.debug(f"Extracted: Category={current_category}, Location={current_location}, Discount={current_discount}, Coupon Name={current_coupon_name}")

                if current_category:
                    session['context']['category'] = current_category
                if current_location:
                    session['context']['location'] = current_location
                if current_discount:
                    session['context']['discount'] = current_discount
                if current_coupon_name:
                    session['context']['coupon_name'] = current_coupon_name
                    session['context']['location'] = None
                else:
                    session['context']['coupon_name'] = current_coupon_name

                category = current_category or session['context']['category']
                location = current_location or session['context']['location']
                discount = current_discount or session['context']['discount']
                coupon_name = current_coupon_name or session['context']['coupon_name']

                logging.debug(f"Final: Query={query}, Category={category}, Location={location}, Coupon Name={coupon_name}, Discount={discount}")

                coupons, fallback = extractor.search_coupons(
                    category=category,
                    location=location,
                    discount=discount,
                    coupon_name=coupon_name,
                    limit=20,
                    active_only=False
                )

                selected_area_name = None
                if location and isinstance(location, dict) and location.get('type') == 'selected_area':
                    selected_area_name = location.get('name')
                elif location and location.get('type') == 'area':
                    selected_area_name = "All areas"

                response = f"Hey, I checked out your request for '{query}'! Here's what I got for you:<br><br>"
                response += f"So, you’re looking for coupons in {_get_area_from_location(location)}"
                if selected_area_name:
                    response += f", specifically around {selected_area_name}"
                response += f". Category? {category or 'Anything goes!'}. "
                response += f"Discount? {_format_discount(discount)}. "
                response += f"Coupon name? {coupon_name or 'Any coupon works!'}.<br>"
                if session['queries']:
                    response += f"By the way, you recently asked about: {', '.join(session['queries'][-2:])}.<br><br>"

                response += "Now, let’s talk deals! 🎉 Here’s what I found:<br>"
                if coupons:
                    active_count = sum(1 for c in coupons if c['status'] == 1)
                    response += f"I dug up {len(coupons)} coupons—{active_count} active and {len(coupons) - active_count} inactive. Check these out:<br><br>"
                    response += '<ul class="list-disc pl-5">'
                    for i, coupon in enumerate(coupons, 1):
                        area_name = _get_area_name(db, coupon.get('selected_area'), coupon.get('territory'), location.get('table') if location else None, coupon.get('area'))
                        coupon_area = _get_coupon_area_name(db, coupon.get('merchant_city') or coupon.get('area'))
                        response += f'<li class="mt-2">{i}. {coupon["name_en"]} ({coupon["name_cn"] or "No Chinese name"})'
                        response += f'<br>🎁 <strong>Discount:</strong> {"No discount" if coupon["percentage"] == 0 else f"{coupon['percentage']}% off"}'
                        status_text = "Active! 🙌" if coupon["status"] == 1 else f"Inactive (expired on {coupon['expiry_date']})"
                        if coupon["status"] == 1 and coupon["quantity"] == 0:
                            status_text += " (out of stock, sorry!)"
                        response += f'<br>📊 <strong>Status:</strong> {status_text}'
                        response += f'<br>🛍️ <strong>Category:</strong> {coupon["category_name_en"] or "Not sure"}'
                        response += f'<br>📍 <strong>Location:</strong> {coupon_area}'
                        response += f'<br>🏙️ <strong>Area:</strong> {area_name}'
                        response += f'<br>🔢 <strong>Quantity:</strong> {coupon["quantity"]}'
                        if coupon.get("coupon_code"):
                            response += f'<br>🔑 <strong>Coupon Code:</strong> {coupon["coupon_code"]}'
                        if coupon.get("qr_image"):
                            response += f'<br>📷 <strong>QR Code:</strong> <img src="/{coupon["qr_image"]}" alt="QR Code" width="100" height="100">'
                        response += '</li>'
                    response += '</ul>'
                else:
                    response += "Oops, no coupons matched that. 😕 Maybe try a different area or category?"

                session['messages'].append({'type': 'system', 'content': Markup(response)})
                logging.debug(f"Added system response. Total messages: {len(session['messages'])}")

                session['queries'].append(query)
                session['queries'] = session['queries'][-3:]
                session.modified = True

            except Exception as e:
                logging.error(f"Error processing query '{query}': {e}")
                error = f"Uh-oh, something went wrong: {str(e)}. Wanna try again? 🤔"
                session['messages'].append({'type': 'system', 'content': error})

        session.modified = True
        return redirect(url_for('index'))

    logging.debug(f"Rendering index with {len(session['messages'])} messages")
    resp = make_response(render_template('index.html', messages=session['messages'], queries=session['queries']))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '-1'
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        logging.debug(f"Login attempt: email={email or 'None'}, password={'*' * len(password) if password else 'None'}")
        if not email:
            flash('Email is required.', 'error')
            logging.warning("Login failed: Email missing")
            return render_template('login.html')
        if not password:
            flash('Password is required.', 'error')
            logging.warning("Login failed: Password missing")
            return render_template('login.html')
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            flash('Invalid email format.', 'error')
            logging.warning(f"Login failed: Invalid email format ({email})")
            return render_template('login.html')
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id, name, email, password FROM users WHERE email = %s AND status = 1 AND deleted_at IS NULL", (email,))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                user_obj = User(id=user['id'], name=user['name'], email=user['email'])
                login_user(user_obj)
                flash('Logged in successfully.', 'success')
                logging.info(f"Login successful: {email}")
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password.', 'error')
                logging.warning(f"Login failed: Invalid credentials for {email}")
        except mysql.connector.Error as e:
            logging.error(f"Database error during login: {e}")
            flash('Login failed due to database error.', 'error')
        finally:
            cursor.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        logging.debug(f"Register attempt: name={name or 'None'}, email={email or 'None'}, password={'*' * len(password) if password else 'None'}")
        if not name:
            flash('Name is required.', 'error')
            logging.warning("Registration failed: Name missing")
            return render_template('register.html')
        if not email:
            flash('Email is required.', 'error')
            logging.warning("Registration failed: Email missing")
            return render_template('register.html')
        if not password:
            flash('Password is required.', 'error')
            logging.warning("Registration failed: Password missing")
            return render_template('register.html')
        if not re.match(r'^[a-zA-Z0-9\s]{3,50}$', name):
            flash('Name must be 3-50 alphanumeric characters.', 'error')
            logging.warning(f"Registration failed: Invalid name format ({name})")
            return render_template('register.html')
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            flash('Invalid email format.', 'error')
            logging.warning(f"Registration failed: Invalid email format ({email})")
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            logging.warning("Registration failed: Password too short")
            return render_template('register.html')
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already exists.', 'error')
                logging.warning(f"Registration failed: Email {email} already exists")
            else:
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute(
                    "INSERT INTO users (name, email, password, user_type, status) VALUES (%s, %s, %s, 0, 1)",
                    (name, email, password_hash)
                )
                flash('Registration successful. Please login.', 'success')
                logging.info(f"Registration successful: {email}")
                return redirect(url_for('login'))
        except mysql.connector.Error as e:
            logging.error(f"Registration error: {e}")
            flash('Registration failed due to database error.', 'error')
        finally:
            cursor.close()
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = %s AND revoked = 0", (user_id,))
        logging.info(f"Revoked tokens for user ID {user_id}")
    except mysql.connector.Error as e:
        logging.error(f"Token revocation error: {e}")
    finally:
        cursor.close()
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

class RegisterAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True, help="Name cannot be blank")
        parser.add_argument('email', type=str, required=True, help="Email cannot be blank")
        parser.add_argument('password', type=str, required=True, help="Password cannot be blank")
        args = parser.parse_args()
        logging.debug(f"API Register attempt: name={args['name']}, email={args['email']}")
        if not re.match(r'^[a-zA-Z0-9\s]{3,50}$', args['name']):
            return {'message': 'Name must be 3-50 alphanumeric characters'}, 400
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', args['email']):
            return {'message': 'Invalid email format'}, 400
        if len(args['password']) < 8:
            return {'message': 'Password must be at least 8 characters'}, 400
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (args['email'],))
            if cursor.fetchone():
                return {'message': 'Email already exists'}, 400
            password_hash = bcrypt.hashpw(args['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (name, email, password, user_type, status) VALUES (%s, %s, %s, 0, 1)",
                (args['name'], args['email'], password_hash)
            )
            return {'message': f'User {args["name"]} created successfully'}, 201
        except mysql.connector.Error as e:
            logging.error(f"Registration API error: {e}")
            return {'message': 'Registration failed'}, 500
        finally:
            cursor.close()

class AuthAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help="Email cannot be blank")
        parser.add_argument('password', type=str, required=True, help="Password cannot be blank")
        args = parser.parse_args()
        logging.debug(f"API Auth attempt: email={args['email']}")
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', args['email']):
            return {'message': 'Invalid email format'}, 400
        if len(args['password']) < 8:
            return {'message': 'Password too short'}, 400
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            logging.debug(f"Querying user with email: {args['email']}")
            cursor.execute("SELECT id, name, email, password FROM users WHERE email = %s AND status = 1 AND deleted_at IS NULL", (args['email'],))
            user = cursor.fetchone()
            logging.debug(f"User fetched: {user}")
            if user:
                logging.debug("Checking password")
                if bcrypt.checkpw(args['password'].encode('utf-8'), user['password'].encode('utf-8')):
                    logging.debug("Password check passed")
                    access_token = create_access_token(identity=user['id'])
                    refresh_token = create_refresh_token(identity=user['id'])
                    # Log token lengths
                    logging.debug(f"Access token length: {len(access_token)}")
                    logging.debug(f"Refresh token length: {len(refresh_token)}")
                    logging.debug("Inserting access token into api_tokens")
                    cursor.execute(
                        "INSERT INTO api_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                        (user['id'], access_token, datetime.utcnow() + timedelta(hours=1))
                    )
                    logging.debug("Inserting refresh token into api_tokens")
                    cursor.execute(
                        "INSERT INTO api_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                        (user['id'], refresh_token, datetime.utcnow() + timedelta(days=30))
                    )
                    logging.debug("Tokens inserted successfully")
                    return {'access_token': access_token, 'refresh_token': refresh_token}, 200
                else:
                    logging.debug("Password check failed")
            else:
                logging.debug("User not found or inactive")
            return {'message': 'Invalid credentials'}, 401
        except mysql.connector.Error as e:
            logging.error(f"Auth error: {e}")
            return {'message': 'Authentication failed'}, 500
        except Exception as e:
            logging.error(f"Unexpected error in AuthAPI: {e}")
            return {'message': 'Authentication failed due to unexpected error'}, 500
        finally:
            cursor.close()
class RefreshAPI(Resource):
    @jwt_required(refresh=True)
    def post(self):
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            if not cursor.fetchone():
                return {'message': 'User not found'}, 404
            access_token = create_access_token(identity=user_id)
            cursor.execute(
                "INSERT INTO api_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
                (user_id, access_token, datetime.utcnow() + timedelta(hours=1))
            )
            return {'access_token': access_token}, 200
        except mysql.connector.Error as e:
            logging.error(f"Refresh error: {e}")
            return {'message': 'Failed to refresh token'}, 500
        finally:
            cursor.close()

class CouponAPI(Resource):
    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('query', type=str, required=True, help="Query cannot be blank")
        args = parser.parse_args()
        if len(args['query']) > 100:
            return {'message': 'Query too long'}, 400
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            if not cursor.fetchone():
                return {'message': 'User not found'}, 404
        finally:
            cursor.close()
        extractor = EnhancedRuleBasedExtractor(db)
        query = args['query'].strip().lower()
        try:
            category = extractor.extract_category(query)
            location = extractor._extract_location_from_query(query)
            discount = extractor._extract_discount_from_query(query)
            coupon_name = extractor._extract_coupon_name_from_query(query)

            logging.debug(f"API Extracted: Query={query}, Category={category}, Location={location}, Discount={discount}, Coupon Name={coupon_name}")

            coupons, fallback = extractor.search_coupons(
                category=category,
                location=location,
                discount=discount,
                coupon_name=coupon_name,
                limit=20,
                active_only=False
            )
            response = {
                'query_analysis': {
                    'query': query,
                    'category': category or "Any",
                    'location': _get_area_from_location(location),
                    'selected_area': location.get('name') if location and location.get('type') == 'selected_area' else ("All areas" if location and location.get('type') == 'area' else "Any"),
                    'coupon_name': coupon_name or "Any",
                    'discount': _format_discount(discount)
                },
                'coupon_results': []
            }
            if coupons:
                for coupon in coupons:
                    area_name = _get_area_name(db, coupon.get('selected_area'), coupon.get('territory'), location.get('table') if location else None, coupon.get('area'))
                    coupon_area = _get_coupon_area_name(db, coupon.get('merchant_city') or coupon.get('area'))
                    status_text = "Active" if coupon['status'] == 1 else f"Inactive (Expired: {coupon['expiry_date']})"
                    if coupon['status'] == 1 and coupon['quantity'] == 0:
                        status_text += " (Out of stock)"
                    response['coupon_results'].append({
                        'name_en': coupon['name_en'],
                        'name_cn': coupon['name_cn'],
                        'discount': f"{coupon['percentage']}% Off" if coupon['percentage'] else "No discount",
                        'status': status_text,
                        'category': coupon['category_name_en'] or "Unknown",
                        'location': coupon_area,
                        'selected_area': area_name,
                        'quantity': coupon['quantity']
                    })
            return response, 200
        except Exception as e:
            logging.error(f"API query error: {e}")
            return {'message': f"Error processing query: {str(e)}"}, 500

class CouponDetailAPI(Resource):
    @jwt_required()
    def get(self, coupon_id):
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            # Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            if not cursor.fetchone():
                return {'message': 'User not found'}, 404

            # Fetch the coupon with related data
            query = """
            SELECT c.*, u.name AS vendor_name, cat.name_en AS category_name_en
            FROM coupons c
            LEFT JOIN users u ON c.created_by = u.id
            LEFT JOIN categories cat ON c.category_id = cat.id
            WHERE c.id = %s AND c.deleted_at IS NULL
            """
            cursor.execute(query, (coupon_id,))
            coupon = cursor.fetchone()
            if not coupon:
                return {'message': f'Coupon with ID {coupon_id} not found'}, 404

            # Map the database fields to the JSON structure
            coupon_data = [
                {
                    "id": coupon["id"],
                    "coupon_id": str(coupon["id"]),
                    "status": coupon["status"],
                    "click_count": int(coupon["click_count"]) if coupon["click_count"] is not None else 0,
                    "category_id": coupon["category_id"],
                    "category_name": coupon["category_name_en"] or "教育&工作坊",
                    "name": coupon["name_en"],
                    "coupon_name": coupon["name_en"] or f"Coupon {coupon['id']}",
                    "name_cn": coupon["name_cn"],
                    "description": coupon["description_en"],
                    "description_cn": coupon["description_cn"],
                    "color": coupon["color"],
                    "type": coupon["type"],
                    "hashtag": coupon["hashtag"],
                    "cash_amount": float(coupon["cash_amount"]) if coupon["cash_amount"] is not None else None,
                    "percentage": float(coupon["percentage"]) if coupon["percentage"] is not None else None,
                    "gift1": coupon["gift1"],
                    "gift2": coupon["gift2"],
                    "is_coupon_none": coupon["is_coupon_none"],
                    "amount": float(coupon["amount"]) if coupon["amount"] is not None else 0,
                    "is_specific_item": coupon["is_specific_item"],
                    "when_purchasing": coupon["when_purchasing"],
                    "regular_price": float(coupon["regular_price"]) if coupon["regular_price"] is not None else 0,
                    "discount_price": float(coupon["discount_price"]) if coupon["discount_price"] is not None else 0,
                    "quantity": int(coupon["quantity"]) if coupon["quantity"] is not None else 0,
                    "purchasing_amount": float(coupon["purchase_price"]) if coupon["purchase_price"] is not None else 0,
                    "expiry_date": str(coupon["expiry_date"]) if coupon["expiry_date"] else None,
                    "expiry_time": str(coupon["expiry_time"]) if coupon["expiry_time"] else None,
                    "expiry_datetime": str(coupon["expiry_datetime"]) if coupon["expiry_datetime"] else None,
                    "additional_terms": coupon["additional_terms_en"],
                    "additional_terms_cn": coupon["additional_terms_cn"],
                    "area": coupon["area"],
                    "selected_area": coupon["selected_area"],
                    "country_id": coupon["country_id"],
                    "state_id": coupon["state_id"],
                    "city_id": coupon["city_id"],
                    "territory": coupon["territory"],
                    "latitude": coupon["latitude"],
                    "longitude": coupon["longitude"],
                    "image": coupon["image"],
                    "offer_image": coupon["offer_image"] or "",
                    "qr_image": coupon["qr_image"] or "",
                    "customer_limit": int(coupon["customer_limit"]) if coupon["customer_limit"] else None,
                    "download_limit": int(coupon["download_limit"]) if coupon["download_limit"] else None,
                    "is_restrict": bool(coupon["is_restrict"]),
                    "scan_count": coupon["scan_count"] if coupon["scan_count"] is not None else 0,
                    "is_scan_limit_reached": bool(coupon["scan_count"] >= (int(coupon["customer_limit"]) if coupon["customer_limit"] else 0)) if coupon["scan_count"] and coupon["customer_limit"] else False,
                    "added_from": coupon["added_from"],
                    "vendor_id": coupon["created_by"],
                    "vendor_name": coupon["vendor_name"],
                    "vendor_profile": "https://redsparkte.a2hosted.com/coupon_go_v2/storage/app/public/images/merchant/796/logo/673d5ca66cd6c.jpeg",
                    "vendor_country": coupon["country_id"],
                    "vendor_state": coupon["state_id"],
                    "vendor_city": coupon["city_id"],
                    "vendor_street_address": "新界荃灣蕙荃路22-66號1G17鋪",
                    "vendor_latitude": coupon["latitude"],
                    "vendor_longitude": coupon["longitude"],
                    "distance": None,
                    "is_coupon_favorite": 0,
                    "is_shop_favorite": 0,
                    "is_coupon_used": 0,
                    "is_limited_notification": 0,
                    "created_by": coupon["created_by"],
                    "branch_id": coupon["branch_id"],
                    "branch_id_temp": coupon["branch_id_temp"],
                    "branch_parent": 0,
                    "branch_count": 0,
                    "has_branch": 0,
                    "updated_by": coupon["updated_by"],
                    "launching_date": str(coupon["launching_date"]) if coupon["launching_date"] else None,
                    "created_at": str(coupon["created_at"]) if coupon["created_at"] else None,
                    "updated_at": str(coupon["updated_at"]) if coupon["updated_at"] else None,
                    "remaining_qr_code": coupon["quantity"],
                    "coupon_offer_text": f"{coupon['gift1']}現金券" if coupon["gift1"] else None,
                    "coupon_short_description": f"消費 “即享“{coupon['gift1']}" if coupon["gift1"] else None
                }
            ]

            return {'coupon': coupon_data}, 200

        except mysql.connector.Error as e:
            logging.error(f"Error fetching coupon {coupon_id}: {e}")
            return {'message': 'Failed to fetch coupon due to database error'}, 500
        finally:
            cursor.close()

class CouponCreateAPI(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            # Verify user exists and has permission to create coupons
            cursor.execute("SELECT id, user_type FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            user = cursor.fetchone()
            if not user:
                return {'message': 'User not found'}, 404
            # Optionally restrict coupon creation to certain user types (e.g., merchants)
            # if user['user_type'] != 1:  # Assuming user_type 1 is for merchants
            #     return {'message': 'Unauthorized to create coupons'}, 403

            # Parse and validate request data
            parser = reqparse.RequestParser()
            parser.add_argument('status', type=int, default=1)
            parser.add_argument('category_id', type=int, required=True, help="Category ID is required")
            parser.add_argument('name_en', type=str, required=True, help="English name is required")
            parser.add_argument('name_cn', type=str)
            parser.add_argument('description_en', type=str)
            parser.add_argument('description_cn', type=str)
            parser.add_argument('color', type=str)
            parser.add_argument('type', type=str)
            parser.add_argument('hashtag', type=str)
            parser.add_argument('cash_amount', type=float)
            parser.add_argument('percentage', type=float)
            parser.add_argument('gift1', type=str)
            parser.add_argument('gift2', type=str)
            parser.add_argument('is_coupon_none', type=int, default=0)
            parser.add_argument('amount', type=float, default=0.0)
            parser.add_argument('is_specific_item', type=str)
            parser.add_argument('when_purchasing', type=str)
            parser.add_argument('regular_price', type=float, default=0.0)
            parser.add_argument('discount_price', type=float, default=0.0)
            parser.add_argument('quantity', type=int, default=0)
            parser.add_argument('purchase_price', type=float, default=0.0)
            parser.add_argument('expiry_date', type=str)
            parser.add_argument('expiry_time', type=str)
            parser.add_argument('additional_terms_en', type=str)
            parser.add_argument('additional_terms_cn', type=str)
            parser.add_argument('area', type=str)
            parser.add_argument('selected_area', type=str)
            parser.add_argument('country_id', type=str)
            parser.add_argument('state_id', type=str)
            parser.add_argument('city_id', type=str)
            parser.add_argument('territory', type=str)
            parser.add_argument('latitude', type=str)
            parser.add_argument('longitude', type=str)
            parser.add_argument('image', type=str)
            parser.add_argument('offer_image', type=str)
            parser.add_argument('customer_limit', type=int)
            parser.add_argument('download_limit', type=int)
            parser.add_argument('is_restrict', type=int, default=0)
            parser.add_argument('added_from', type=int, default=0)
            parser.add_argument('branch_id', type=int, default=0)
            parser.add_argument('branch_id_temp', type=str)
            parser.add_argument('launching_date', type=str)
            args = parser.parse_args()

            # Validate required fields and formats
            if len(args['name_en']) > 255:
                return {'message': 'English name must not exceed 255 characters'}, 400
            if args['name_cn'] and len(args['name_cn']) > 255:
                return {'message': 'Chinese name must not exceed 255 characters'}, 400
            if args['hashtag'] and len(args['hashtag']) > 150:
                return {'message': 'Hashtag must not exceed 150 characters'}, 400
            if args['percentage'] and (args['percentage'] < 0 or args['percentage'] > 100):
                return {'message': 'Percentage must be between 0 and 100'}, 400

            # Convert date/time strings to proper formats
            expiry_date = args['expiry_date'] if args['expiry_date'] else None
            expiry_time = args['expiry_time'] if args['expiry_time'] else None
            launching_date = args['launching_date'] if args['launching_date'] else None

            # Insert the new coupon
            insert_query = """
            INSERT INTO coupons (
                status, click_count, category_id, name_en, name_cn, description_en, description_cn, color, type, hashtag,
                cash_amount, percentage, gift1, gift2, is_coupon_none, amount, is_specific_item, when_purchasing,
                regular_price, discount_price, quantity, purchase_price, expiry_date, expiry_time, additional_terms_en,
                additional_terms_cn, area, selected_area, country_id, state_id, city_id, territory, latitude, longitude,
                image, offer_image, customer_limit, download_limit, is_restrict, scan_count, added_from, created_by,
                branch_id, branch_id_temp, updated_by, launching_date, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (
                args['status'], 0, args['category_id'], args['name_en'], args['name_cn'], args['description_en'],
                args['description_cn'], args['color'], args['type'], args['hashtag'], args['cash_amount'],
                args['percentage'], args['gift1'], args['gift2'], args['is_coupon_none'], args['amount'],
                args['is_specific_item'], args['when_purchasing'], args['regular_price'], args['discount_price'],
                args['quantity'], args['purchase_price'], expiry_date, expiry_time, args['additional_terms_en'],
                args['additional_terms_cn'], args['area'], args['selected_area'], args['country_id'], args['state_id'],
                args['city_id'], args['territory'], args['latitude'], args['longitude'], args['image'],
                args['offer_image'], args['customer_limit'], args['download_limit'], args['is_restrict'], 0,
                args['added_from'], user_id, args['branch_id'], args['branch_id_temp'], user_id, launching_date,
                datetime.utcnow(), datetime.utcnow()
            ))

            coupon_id = cursor.lastrowid
            return {'message': f'Coupon {coupon_id} created successfully'}, 201

        except mysql.connector.Error as e:
            logging.error(f"Error creating coupon: {e}")
            return {'message': 'Failed to create coupon due to database error'}, 500
        finally:
            cursor.close()

class CouponUpdateAPI(Resource):
    @jwt_required()
    def put(self, coupon_id):
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            # Verify user exists
            cursor.execute("SELECT id, user_type FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            user = cursor.fetchone()
            if not user:
                return {'message': 'User not found'}, 404

            # Verify coupon exists and user has permission to update it
            cursor.execute("SELECT created_by FROM coupons WHERE id = %s AND deleted_at IS NULL", (coupon_id,))
            coupon = cursor.fetchone()
            if not coupon:
                return {'message': f'Coupon with ID {coupon_id} not found'}, 404
            if coupon['created_by'] != user_id:
                return {'message': 'Unauthorized to update this coupon'}, 403

            # Parse and validate request data
            parser = reqparse.RequestParser()
            parser.add_argument('status', type=int)
            parser.add_argument('category_id', type=int)
            parser.add_argument('name_en', type=str)
            parser.add_argument('name_cn', type=str)
            parser.add_argument('description_en', type=str)
            parser.add_argument('description_cn', type=str)
            parser.add_argument('color', type=str)
            parser.add_argument('type', type=str)
            parser.add_argument('hashtag', type=str)
            parser.add_argument('cash_amount', type=float)
            parser.add_argument('percentage', type=float)
            parser.add_argument('gift1', type=str)
            parser.add_argument('gift2', type=str)
            parser.add_argument('is_coupon_none', type=int)
            parser.add_argument('amount', type=float)
            parser.add_argument('is_specific_item', type=str)
            parser.add_argument('when_purchasing', type=str)
            parser.add_argument('regular_price', type=float)
            parser.add_argument('discount_price', type=float)
            parser.add_argument('quantity', type=int)
            parser.add_argument('purchase_price', type=float)
            parser.add_argument('expiry_date', type=str)
            parser.add_argument('expiry_time', type=str)
            parser.add_argument('additional_terms_en', type=str)
            parser.add_argument('additional_terms_cn', type=str)
            parser.add_argument('area', type=str)
            parser.add_argument('selected_area', type=str)
            parser.add_argument('country_id', type=str)
            parser.add_argument('state_id', type=str)
            parser.add_argument('city_id', type=str)
            parser.add_argument('territory', type=str)
            parser.add_argument('latitude', type=str)
            parser.add_argument('longitude', type=str)
            parser.add_argument('image', type=str)
            parser.add_argument('offer_image', type=str)
            parser.add_argument('customer_limit', type=int)
            parser.add_argument('download_limit', type=int)
            parser.add_argument('is_restrict', type=int)
            parser.add_argument('added_from', type=int)
            parser.add_argument('branch_id', type=int)
            parser.add_argument('branch_id_temp', type=str)
            parser.add_argument('launching_date', type=str)
            args = parser.parse_args()

            # Fetch current coupon data to merge with updates
            cursor.execute("SELECT * FROM coupons WHERE id = %s", (coupon_id,))
            current_coupon = cursor.fetchone()

            # Validate updated fields
            if args['name_en'] and len(args['name_en']) > 255:
                return {'message': 'English name must not exceed 255 characters'}, 400
            if args['name_cn'] and len(args['name_cn']) > 255:
                return {'message': 'Chinese name must not exceed 255 characters'}, 400
            if args['hashtag'] and len(args['hashtag']) > 150:
                return {'message': 'Hashtag must not exceed 150 characters'}, 400
            if args['percentage'] and (args['percentage'] < 0 or args['percentage'] > 100):
                return {'message': 'Percentage must be between 0 and 100'}, 400

            # Merge updated fields with existing data
            update_data = {
                'status': args['status'] if args['status'] is not None else current_coupon['status'],
                'category_id': args['category_id'] if args['category_id'] is not None else current_coupon['category_id'],
                'name_en': args['name_en'] if args['name_en'] is not None else current_coupon['name_en'],
                'name_cn': args['name_cn'] if args['name_cn'] is not None else current_coupon['name_cn'],
                'description_en': args['description_en'] if args['description_en'] is not None else current_coupon['description_en'],
                'description_cn': args['description_cn'] if args['description_cn'] is not None else current_coupon['description_cn'],
                'color': args['color'] if args['color'] is not None else current_coupon['color'],
                'type': args['type'] if args['type'] is not None else current_coupon['type'],
                'hashtag': args['hashtag'] if args['hashtag'] is not None else current_coupon['hashtag'],
                'cash_amount': args['cash_amount'] if args['cash_amount'] is not None else current_coupon['cash_amount'],
                'percentage': args['percentage'] if args['percentage'] is not None else current_coupon['percentage'],
                'gift1': args['gift1'] if args['gift1'] is not None else current_coupon['gift1'],
                'gift2': args['gift2'] if args['gift2'] is not None else current_coupon['gift2'],
                'is_coupon_none': args['is_coupon_none'] if args['is_coupon_none'] is not None else current_coupon['is_coupon_none'],
                'amount': args['amount'] if args['amount'] is not None else current_coupon['amount'],
                'is_specific_item': args['is_specific_item'] if args['is_specific_item'] is not None else current_coupon['is_specific_item'],
                'when_purchasing': args['when_purchasing'] if args['when_purchasing'] is not None else current_coupon['when_purchasing'],
                'regular_price': args['regular_price'] if args['regular_price'] is not None else current_coupon['regular_price'],
                'discount_price': args['discount_price'] if args['discount_price'] is not None else current_coupon['discount_price'],
                'quantity': args['quantity'] if args['quantity'] is not None else current_coupon['quantity'],
                'purchase_price': args['purchase_price'] if args['purchase_price'] is not None else current_coupon['purchase_price'],
                'expiry_date': args['expiry_date'] if args['expiry_date'] is not None else current_coupon['expiry_date'],
                'expiry_time': args['expiry_time'] if args['expiry_time'] is not None else current_coupon['expiry_time'],
                'additional_terms_en': args['additional_terms_en'] if args['additional_terms_en'] is not None else current_coupon['additional_terms_en'],
                'additional_terms_cn': args['additional_terms_cn'] if args['additional_terms_cn'] is not None else current_coupon['additional_terms_cn'],
                'area': args['area'] if args['area'] is not None else current_coupon['area'],
                'selected_area': args['selected_area'] if args['selected_area'] is not None else current_coupon['selected_area'],
                'country_id': args['country_id'] if args['country_id'] is not None else current_coupon['country_id'],
                'state_id': args['state_id'] if args['state_id'] is not None else current_coupon['state_id'],
                'city_id': args['city_id'] if args['city_id'] is not None else current_coupon['city_id'],
                'territory': args['territory'] if args['territory'] is not None else current_coupon['territory'],
                'latitude': args['latitude'] if args['latitude'] is not None else current_coupon['latitude'],
                'longitude': args['longitude'] if args['longitude'] is not None else current_coupon['longitude'],
                'image': args['image'] if args['image'] is not None else current_coupon['image'],
                'offer_image': args['offer_image'] if args['offer_image'] is not None else current_coupon['offer_image'],
                'customer_limit': args['customer_limit'] if args['customer_limit'] is not None else current_coupon['customer_limit'],
                'download_limit': args['download_limit'] if args['download_limit'] is not None else current_coupon['download_limit'],
                'is_restrict': args['is_restrict'] if args['is_restrict'] is not None else current_coupon['is_restrict'],
                'added_from': args['added_from'] if args['added_from'] is not None else current_coupon['added_from'],
                'branch_id': args['branch_id'] if args['branch_id'] is not None else current_coupon['branch_id'],
                'branch_id_temp': args['branch_id_temp'] if args['branch_id_temp'] is not None else current_coupon['branch_id_temp'],
                'launching_date': args['launching_date'] if args['launching_date'] is not None else current_coupon['launching_date']
            }

            # Update the coupon
            update_query = """
            UPDATE coupons SET
                status = %s, category_id = %s, name_en = %s, name_cn = %s, description_en = %s, description_cn = %s,
                color = %s, type = %s, hashtag = %s, cash_amount = %s, percentage = %s, gift1 = %s, gift2 = %s,
                is_coupon_none = %s, amount = %s, is_specific_item = %s, when_purchasing = %s, regular_price = %s,
                discount_price = %s, quantity = %s, purchase_price = %s, expiry_date = %s, expiry_time = %s,
                additional_terms_en = %s, additional_terms_cn = %s, area = %s, selected_area = %s, country_id = %s,
                state_id = %s, city_id = %s, territory = %s, latitude = %s, longitude = %s, image = %s, offer_image = %s,
                customer_limit = %s, download_limit = %s, is_restrict = %s, added_from = %s, branch_id = %s,
                branch_id_temp = %s, updated_by = %s, launching_date = %s, updated_at = %s
            WHERE id = %s
            """
            cursor.execute(update_query, (
                update_data['status'], update_data['category_id'], update_data['name_en'], update_data['name_cn'],
                update_data['description_en'], update_data['description_cn'], update_data['color'], update_data['type'],
                update_data['hashtag'], update_data['cash_amount'], update_data['percentage'], update_data['gift1'],
                update_data['gift2'], update_data['is_coupon_none'], update_data['amount'], update_data['is_specific_item'],
                update_data['when_purchasing'], update_data['regular_price'], update_data['discount_price'],
                update_data['quantity'], update_data['purchase_price'], update_data['expiry_date'],
                update_data['expiry_time'], update_data['additional_terms_en'], update_data['additional_terms_cn'],
                update_data['area'], update_data['selected_area'], update_data['country_id'], update_data['state_id'],
                update_data['city_id'], update_data['territory'], update_data['latitude'], update_data['longitude'],
                update_data['image'], update_data['offer_image'], update_data['customer_limit'],
                update_data['download_limit'], update_data['is_restrict'], update_data['added_from'],
                update_data['branch_id'], update_data['branch_id_temp'], user_id, update_data['launching_date'],
                datetime.utcnow(), coupon_id
            ))

            return {'message': f'Coupon {coupon_id} updated successfully'}, 200

        except mysql.connector.Error as e:
            logging.error(f"Error updating coupon {coupon_id}: {e}")
            return {'message': 'Failed to update coupon due to database error'}, 500
        finally:
            cursor.close()

class CouponDeleteAPI(Resource):
    @jwt_required()
    def delete(self, coupon_id):
        user_id = get_jwt_identity()
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            # Verify user exists
            cursor.execute("SELECT id, user_type FROM users WHERE id = %s AND status = 1 AND deleted_at IS NULL", (user_id,))
            user = cursor.fetchone()
            if not user:
                return {'message': 'User not found'}, 404

            # Verify coupon exists and user has permission to delete it
            cursor.execute("SELECT created_by FROM coupons WHERE id = %s AND deleted_at IS NULL", (coupon_id,))
            coupon = cursor.fetchone()
            if not coupon:
                return {'message': f'Coupon with ID {coupon_id} not found'}, 404
            if coupon['created_by'] != user_id:
                return {'message': 'Unauthorized to delete this coupon'}, 403

            # Soft delete the coupon
            cursor.execute("UPDATE coupons SET deleted_at = %s WHERE id = %s", (datetime.utcnow(), coupon_id))
            return {'message': f'Coupon {coupon_id} deleted successfully'}, 200

        except mysql.connector.Error as e:
            logging.error(f"Error deleting coupon {coupon_id}: {e}")
            return {'message': 'Failed to delete coupon due to database error'}, 500
        finally:
            cursor.close()

# Existing API endpoints
api.add_resource(RegisterAPI, '/api/register')
api.add_resource(AuthAPI, '/api/auth')
api.add_resource(RefreshAPI, '/api/refresh')
api.add_resource(CouponAPI, '/api/coupons')
api.add_resource(CouponDetailAPI, '/api/coupon/<int:coupon_id>')
# New endpoints for CRUD operations
api.add_resource(CouponCreateAPI, '/api/coupon')
api.add_resource(CouponUpdateAPI, '/api/coupon/<int:coupon_id>')
api.add_resource(CouponDeleteAPI, '/api/coupon/<int:coupon_id>')

if __name__ == '__main__':
    print("Starting Flask app...")
    app.run(debug=True, host='0.0.0.0', port=5001)