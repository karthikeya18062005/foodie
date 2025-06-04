from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import re
from datetime import datetime, timedelta
import random
import os
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["foodie_db"]
users_collection = db["users"]
admin_collection = db["admin"]
restaurant_collection = db["restaurant"]
orders_collection = db["orders"]

# Configure upload folder for payment proofs
UPLOAD_FOLDER = 'static/uploads/payment_proofs'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create indexes for unique fields
users_collection.create_index([("email", 1)], unique=True)
admin_collection.create_index([("email", 1)], unique=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check admin first
        admin = admin_collection.find_one({"email": email})
        if admin and (admin['password'] == password):
            session['admin_id'] = str(admin['_id'])
            session['email'] = admin['email']
            session['is_admin'] = True
            print("Admin logged in:", session)
            return jsonify({"status": "success", "message": "Admin login successful!", "redirect": url_for('admin_dashboard')})
        
        # Check restaurant account
        restaurant = restaurant_collection.find_one({"email": email})
        if restaurant and (restaurant['password'] == password):
            session['restaurant_id'] = str(restaurant['_id'])
            session['email'] = restaurant['email']
            session['is_restaurant'] = True
            print("Restaurant logged in:", session)
            return jsonify({"status": "success", "message": "Restaurant login successful!", "redirect": url_for('restaurant_admin')})
        
        # Check regular user
        user = users_collection.find_one({"email": email})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['is_admin'] = False
            session['is_restaurant'] = False
            print("User logged in:", session)
            
            # Check if there's a next URL to redirect to
            next_url = session.pop('next', None)
            if next_url:
                return jsonify({"status": "success", "message": "Login successful!", "redirect": next_url})
            return jsonify({"status": "success", "message": "Login successful!", "redirect": url_for('home')})
        
        return jsonify({"status": "error", "message": "Invalid email or password"})

    # For GET requests, check if there's a next parameter
    next_url = request.args.get('next')
    if next_url:
        session['next'] = next_url
    return render_template('loginAndRegistration.html')

@app.route('/restaurant/admin')
def restaurant_admin():
    if not session.get('is_restaurant', False):
        return redirect(url_for('login'))
    
    # Get restaurant details
    restaurant = restaurant_collection.find_one({"_id": ObjectId(session['restaurant_id'])})
    if not restaurant:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('restaurant_admin.html', restaurant=restaurant)

@app.route('/api/restaurant/update', methods=['POST'])
def update_restaurant():
    if not session.get('is_restaurant', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        data = request.json
        restaurant_id = ObjectId(session['restaurant_id'])
        
        # Don't allow updating email or password through this endpoint
        if 'email' in data:
            del data['email']
        if 'password' in data:
            del data['password']
        
        # Update restaurant
        result = restaurant_collection.update_one(
            {"_id": restaurant_id},
            {"$set": data}
        )
        
        if result.modified_count > 0:
            return jsonify({"status": "success", "message": "Restaurant updated successfully"})
        return jsonify({"status": "error", "message": "No changes made"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/restaurant/menu/add', methods=['POST'])
def add_menu_item():
    if not session.get('is_restaurant', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        item = request.json
        restaurant_id = ObjectId(session['restaurant_id'])
        
        # Validate required fields
        if not all(key in item for key in ['item', 'price', 'menu_item_url']):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400
        
        # Add the new menu item
        result = restaurant_collection.update_one(
            {"_id": restaurant_id},
            {"$push": {"menu": item}}
        )
        
        if result.modified_count > 0:
            return jsonify({"status": "success", "message": "Menu item added successfully"})
        return jsonify({"status": "error", "message": "Failed to add menu item"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/restaurant/menu/delete', methods=['POST'])
def delete_menu_item():
    if not session.get('is_restaurant', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        item_name = request.json.get('item_name')
        restaurant_id = ObjectId(session['restaurant_id'])
        
        # Remove the menu item
        result = restaurant_collection.update_one(
            {"_id": restaurant_id},
            {"$pull": {"menu": {"item": item_name}}}
        )
        
        if result.modified_count > 0:
            return jsonify({"status": "success", "message": "Menu item deleted successfully"})
        return jsonify({"status": "error", "message": "Menu item not found"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    # Get total users count
    total_users = users_collection.count_documents({})
    
    # Get total restaurants count
    total_restaurants = restaurant_collection.count_documents({})
    
    # Get recent users
    users = list(users_collection.find({}, {'email': 1, 'phone': 1, 'created_at': 1})
                .sort('_id', -1)
                .limit(10))
    
    # Get restaurants
    restaurants = list(restaurant_collection.find({}, {
        'name': 1, 
        'cuisine': 1, 
        'rating': 1
    }).sort('rating', -1))

    # Get all admins
    admins = list(admin_collection.find({}, {'email': 1, 'created_at': 1}))
    
    # Convert ObjectId to string for JSON serialization
    for user in users:
        user['_id'] = str(user['_id'])
    
    for restaurant in restaurants:
        restaurant['_id'] = str(restaurant['_id'])

    for admin in admins:
        admin['_id'] = str(admin['_id'])
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_restaurants=total_restaurants,
                         users=users,
                         restaurants=restaurants,
                         admins=admins)

@app.route('/admin/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        result = users_collection.delete_one({"_id": ObjectId(user_id)})
        if result.deleted_count > 0:
            return jsonify({"status": "success", "message": "User deleted successfully"})
        return jsonify({"status": "error", "message": "User not found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/delete_restaurant/<restaurant_id>', methods=['DELETE'])
def delete_restaurant(restaurant_id):
    if not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        result = restaurant_collection.delete_one({"_id": ObjectId(restaurant_id)})
        if result.deleted_count > 0:
            return jsonify({"status": "success", "message": "Restaurant deleted successfully"})
        return jsonify({"status": "error", "message": "Restaurant not found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/add_admin', methods=['POST'])
def add_admin():
    if not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required"})
    
    try:
        admin_collection.insert_one({
            "email": email,
            "password": password,  # Note: In a production environment, you should hash this password
            "created_at": datetime.utcnow()
        })
        return jsonify({"status": "success", "message": "Admin added successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/add_restaurant', methods=['POST'])
def add_restaurant():
    if not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    try:
        restaurant_data = request.json
        restaurant_collection.insert_one(restaurant_data)
        return jsonify({"status": "success", "message": "Restaurant added successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/delete_admin/<admin_id>', methods=['DELETE'])
def delete_admin(admin_id):
    if not session.get('is_admin', False):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    # Prevent admin from deleting themselves
    if str(admin_id) == session.get('admin_id'):
        return jsonify({"status": "error", "message": "Cannot delete your own admin account"}), 400
    
    try:
        # Check if this is the last admin
        if admin_collection.count_documents({}) <= 1:
            return jsonify({"status": "error", "message": "Cannot delete the last admin account"}), 400
        
        result = admin_collection.delete_one({"_id": ObjectId(admin_id)})
        if result.deleted_count > 0:
            return jsonify({"status": "success", "message": "Admin deleted successfully"})
        return jsonify({"status": "error", "message": "Admin not found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        phone = request.form.get('phone')

        # Validation
        if not all([password, confirm_password, email, phone]):
            return jsonify({"status": "error", "message": "All fields are required"})

        if password != confirm_password:
            return jsonify({"status": "error", "message": "Passwords do not match"})

        # Email validation
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            return jsonify({"status": "error", "message": "Invalid email format"})

        # Phone validation
        phone_pattern = r'^\d{10}$'
        if not re.match(phone_pattern, phone):
            return jsonify({"status": "error", "message": "Invalid phone number (10 digits required)"})

        # Check if email already exists
        if users_collection.find_one({"email": email}):
            return jsonify({"status": "error", "message": "Email already registered"})

        # Create new user
        new_user = {
            "email": email,
            "password": generate_password_hash(password),
            "phone": phone,
            "created_at": datetime.utcnow()
        }

        try:
            users_collection.insert_one(new_user)
            return jsonify({
                "status": "success", 
                "message": "Registration successful! Please login.", 
                "redirect": url_for('login')
            })
        except Exception as e:
            return jsonify({"status": "error", "message": "Registration failed"})

    return render_template('loginAndRegistration.html')

@app.route('/home')
def home():
    print("Current session:", session)
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")
        return redirect(url_for('login'))
    
    # Get user's order history
    user_orders = list(orders_collection.find(
        {"user_id": session['user_id']},
        sort=[("created_at", -1)]  # Sort by newest first
    ))
    
    # Convert ObjectId to string for JSON serialization
    for order in user_orders:
        order['_id'] = str(order['_id'])
        order['created_at'] = order['created_at'].strftime("%Y-%m-%d %H:%M:%S")
    
    print("User is logged in with ID:", session['user_id'])
    return render_template('home.html', orders=user_orders)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/restaurants/search')
def search_restaurants():
    query = request.args.get('q', '')
    mood = request.args.get('mood', '')
    cuisine = request.args.get('cuisine', '')
    city = request.args.get('city', '')
    price = request.args.get('price', '')
    
    # Build the search filter
    search_filter = {}
    
    if query:
        search_filter['$or'] = [
            {'name': {'$regex': query, '$options': 'i'}},
            {'cuisine': {'$regex': query, '$options': 'i'}},
            {'tags': {'$regex': query, '$options': 'i'}},
            {'city': {'$regex': query, '$options': 'i'}}
        ]
    
    if mood:
        search_filter['moods'] = mood
    
    if cuisine:
        search_filter['cuisine'] = cuisine
    
    if city:
        search_filter['city'] = city
    
    if price:
        search_filter['price_level'] = price
    
    # Get restaurants matching the filter
    restaurants = list(restaurant_collection.find(search_filter))
    
    # If no specific filters are applied and no search query, return all restaurants
    if not (query or mood or cuisine or city or price):
        restaurants = list(restaurant_collection.find())
    
    # Convert ObjectId to string for JSON serialization
    for restaurant in restaurants:
        restaurant['_id'] = str(restaurant['_id'])
    
    return jsonify(restaurants)

@app.route('/api/restaurants/random')
def get_random_restaurant():
    mood = request.args.get('mood', '')
    
    # Build the filter
    filter_query = {}
    if mood:
        filter_query['moods'] = mood
    
    # Get the count of matching restaurants
    count = restaurant_collection.count_documents(filter_query)
    
    if count == 0:
        return jsonify({'error': 'No restaurants found'}), 404
    
    # Get a random restaurant
    random_restaurant = restaurant_collection.aggregate([
        {'$match': filter_query},
        {'$sample': {'size': 1}}
    ]).next()
    
    # Convert ObjectId to string
    random_restaurant['_id'] = str(random_restaurant['_id'])
    
    return jsonify(random_restaurant)

@app.route('/api/restaurants/trending')
def get_trending_restaurants():
    trending = list(restaurant_collection.find({'is_trending': True}).limit(6))
    
    # Convert ObjectId to string for JSON serialization
    for restaurant in trending:
        restaurant['_id'] = str(restaurant['_id'])
    
    return jsonify(trending)

@app.route('/api/restaurants/recommended')
def get_recommended_restaurants():
    # For now, return top-rated restaurants as recommendations
    recommended = list(restaurant_collection.find().sort('rating', -1).limit(6))
    
    # Convert ObjectId to string for JSON serialization
    for restaurant in recommended:
        restaurant['_id'] = str(restaurant['_id'])
    
    return jsonify(recommended)

@app.route('/api/check-session')
def check_session():
    is_logged_in = 'user_id' in session
    return jsonify({'logged_in': is_logged_in})

@app.route('/restaurant/<restaurant_id>')
def restaurant_details(restaurant_id):
    # Check if user is logged in
    if 'user_id' not in session:
        print("User not logged in, redirecting to login")
        session['next'] = request.path
        return redirect(url_for('login'))
    
    try:
        # Find the restaurant by ID
        restaurant = restaurant_collection.find_one({"_id": ObjectId(restaurant_id)})
        print("Found restaurant:", bool(restaurant))
        
        if not restaurant:
            print("Restaurant not found")
            return redirect(url_for('home'))
        
        # Create a clean dictionary for the template
        restaurant_data = {
            '_id': str(restaurant['_id']),
            'name': restaurant.get('name', ''),
            'description': restaurant.get('description', ''),
            'address': restaurant.get('address', ''),
            'city': restaurant.get('city', ''),
            'cuisine': restaurant.get('cuisine', []),
            'price_level': restaurant.get('price_level', '$'),
            'rating': restaurant.get('rating', 'N/A'),
            'image_url': restaurant.get('image_url', ''),
            'phone': restaurant.get('phone', 'N/A'),
            'email': restaurant.get('email', 'N/A'),
            'website': restaurant.get('website', ''),
            'location_url': restaurant.get('location_url', '#'),
            'menu': [],
            'hours': restaurant.get('hours', {
                'Monday': '9:00 AM - 10:00 PM',
                'Tuesday': '9:00 AM - 10:00 PM',
                'Wednesday': '9:00 AM - 10:00 PM',
                'Thursday': '9:00 AM - 10:00 PM',
                'Friday': '9:00 AM - 11:00 PM',
                'Saturday': '10:00 AM - 11:00 PM',
                'Sunday': '10:00 AM - 10:00 PM'
            })
        }

        # Process menu items
        menu_items = restaurant.get('menu', [])
        if isinstance(menu_items, list):
            restaurant_data['menu'] = [
                {
                    'name': item.get('item', ''),
                    'price': item.get('price', ''),
                    'image_url': item.get('menu_item_url', '')
                }
                for item in menu_items
                if isinstance(item, dict)
            ]
        
        print("Restaurant data prepared:", restaurant_data)
        return render_template('restaurant_details.html', restaurant=restaurant_data)
    
    except Exception as e:
        print(f"Error in restaurant_details: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('home'))

@app.route('/payment')
def payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('payment.html')

@app.route('/api/process-payment', methods=['POST'])
def process_payment():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Please login first"}), 401
    
    try:
        # Get form data
        data = request.form
        payment_proof = request.files.get('paymentProof')
        
        if not payment_proof:
            return jsonify({"status": "error", "message": "Payment proof is required"}), 400
        
        # Save payment proof
        filename = secure_filename(payment_proof.filename)
        payment_proof.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Create order in database
        order = {
            "user_id": session['user_id'],
            "name": data.get('name'),
            "phone": data.get('phone'),
            "address": data.get('address'),
            "order_items": json.loads(data.get('items', '[]')),
            "total_amount": float(data.get('total_amount', 0)),
            "payment_proof": filename,
            "status": "pending",
            "created_at": datetime.utcnow()
        }
        
        orders_collection.insert_one(order)
        
        return jsonify({
            "status": "success",
            "message": "Order placed successfully!",
            "redirect": url_for('home')
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/orders/<order_id>/cancel', methods=['POST'])
def cancel_order(order_id):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Please login first"}), 401
    
    try:
        # Find the order
        order = orders_collection.find_one({
            "_id": ObjectId(order_id),
            "user_id": session['user_id']
        })
        
        if not order:
            return jsonify({"status": "error", "message": "Order not found"}), 404
        
        if order['status'] != 'pending':
            return jsonify({"status": "error", "message": "Only pending orders can be cancelled"}), 400
        
        # Update order status
        orders_collection.update_one(
            {"_id": ObjectId(order_id)},
            {"$set": {"status": "cancelled"}}
        )
        
        return jsonify({
            "status": "success",
            "message": "Order cancelled successfully"
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=7)  # Set session to last 7 days

if __name__ == '__main__':
    app.run(debug=True)