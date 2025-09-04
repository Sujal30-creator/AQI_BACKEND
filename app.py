import csv
import os
import datetime
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import traceback
import pandas as pd
import pickle
import matplotlib
matplotlib.use('Agg')

# Optional visualization import (preserving your original logic)
try:
    import Updated_Visualization as vis
except ImportError:
    vis = None

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Requests

# Render PostgreSQL compatibility (only change needed for deployment)
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///users.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

# YOUR ORIGINAL DATABASE MODELS - UNCHANGED
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)

class AQIRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    month_index = db.Column(db.Integer, nullable=False)
    aqi_value = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# YOUR ORIGINAL DATA - UNCHANGED
AQI_VALUES_BY_MONTH = []

def load_aqi_data():
    global AQI_VALUES_BY_MONTH
    try:
        with open('RS_Session_262_AU_2113_1.csv', mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['City'] == 'Delhi':
                    AQI_VALUES_BY_MONTH = [
                        330, 255, 200, 245, 314, 123,
                        215, 265, 345, 312, 360
                    ]
                    break
    except FileNotFoundError:
        # Fallback if CSV file is not found
        AQI_VALUES_BY_MONTH = [330, 255, 200, 245, 314, 123, 215, 265, 345, 312, 360]

load_aqi_data()

# YOUR ORIGINAL AQI ROUTE - UNCHANGED
@app.route('/aqi/<int:month_index>', methods=['POST'])
def get_aqi_by_month(month_index):
    try:
        if not 1 <= month_index <= 12:
            return jsonify({"error": "Invalid month", "message": "Month index must be between 1-12"}), 400
        aqi_value = AQI_VALUES_BY_MONTH[month_index - 1]
        return jsonify({"month_index": month_index, "aqi": aqi_value})
    except Exception as e:
        return jsonify({"error": "Server error", "message": str(e)}), 500

# YOUR ORIGINAL DELHI NEWS ROUTE - UNCHANGED
@app.route('/delhi-news', methods=['GET'])
def delhi_air_news():
    try:
        url = "https://newsapi.org/v2/everything?q=delhi%20aqi&language=en&sortBy=relevancy&pageSize=3&apiKey=9afbb7aabe0d49e78dd57399e5e1ffb9"
        params = {
            'q': 'delhi air quality OR delhi pollution',
            'language': 'en',
            'sortBy': 'publishedAt',
            'apiKey': os.getenv("NEWS_API_KEY", "9afbb7aabe0d49e78dd57399e5e1ffb9"),
            'pageSize': 5
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        articles = []
        for article in response.json().get('articles', []):
            articles.append({
                "title": article.get("title", ""),
                "source": article.get("source", {}).get("name", ""),
                "url": article.get("url", ""),
                "published": article.get("publishedAt", "")
            })
        return jsonify({"success": True, "articles": articles})
    except Exception as e:
        return jsonify({
            "error": f"News API Error: {str(e)}",
            "solution": "Check API key or try again later"
        }), 500

# YOUR ORIGINAL DELHI FORECAST ROUTE - UNCHANGED
@app.route('/delhi-forecast', methods=['GET'])
def delhi_pollution_forecast():
    try:
        url = "http://api.openweathermap.org/data/2.5/air_pollution/forecast"
        params = {
            'lat': 28.6139,
            'lon': 77.2090,
            'appid': os.getenv("OPENWEATHER_KEY")
        }
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        forecast = []
        for item in response.json().get('list', []):
            dt = datetime.datetime.fromtimestamp(item['dt'])
            forecast.append({
                "datetime": dt.isoformat(),
                "aqi": item['main']['aqi'],
                "components": item['components']
            })
        return jsonify({"success": True, "forecast": forecast})
    except Exception as e:
        return jsonify({
            "error": f"Weather API Error: {str(e)}",
            "solution": "Check API key or coordinates"
        }), 500

# YOUR ORIGINAL VALIDATION FUNCTION - UNCHANGED
def validate_json(payload, required_fields):
    if not payload:
        return False
    return all(field in payload and payload[field] for field in required_fields)

# YOUR ORIGINAL MODEL AND DATASET LOADING - UNCHANGED
base_dir = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(base_dir, "rf_model.pkl"), "rb") as f:
        rf_model = pickle.load(f)
    print("Random Forest model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    rf_model = None

try:
    dataset_path = os.path.join(base_dir, 'Final_Dataset.csv')
    df = pd.read_csv(dataset_path)
    print(f"Successfully loaded AQI dataset from {dataset_path}")
except Exception as e:
    print(f"Error loading AQI dataset: {e}")
    df = pd.DataFrame()

# YOUR ORIGINAL CHECK-USER ROUTE - UNCHANGED
@app.route('/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    if not validate_json(data, ['username']):
        return jsonify({'error': 'Username is required'}), 400
    exists = User.query.filter_by(username=data['username']).first() is not None
    return jsonify({'exists': exists}), 200

# YOUR ORIGINAL SIGNUP ROUTE - UNCHANGED
@app.route('/signup', methods=['POST'])
def signup():
    try:
        raw_data = request.get_data(as_text=True)
        print("RAW REQUEST BODY:", raw_data)

        data = request.get_json(force=True)  # Use force=True to avoid None
        print("Parsed JSON:", data)

        # Debug prints
        print("username:", data.get("username"))
        print("password:", data.get("password"))
        print("category:", data.get("category"))

        # Improved validation: checks for missing or blank values
        required_fields = ['username', 'password', 'category']
        missing = [f for f in required_fields if not str(data.get(f)).strip()]
        print("Checked missing fields:", {f: data.get(f) for f in ['username', 'password', 'category']})

        if missing:
            return jsonify({'error': f'Missing or empty fields: {missing}'}), 400
        
        print("Checking if user already exists...")
        print("User exists:", User.query.filter_by(username=data['username']).first())
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(
            username=data['username'].strip(),
            password=hashed_password,
            category=data['category'].strip()
        )
        db.session.add(new_user)
        db.session.commit()

        print(f"✅ User '{new_user.username}' successfully created.")

        return jsonify({
            'message': 'User created successfully',
            'user': {
                'username': new_user.username,
                'category': new_user.category
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        print("❌ Exception during signup:", e)
        return jsonify({'error': str(e)}), 500

# YOUR ORIGINAL LOGIN ROUTE - UNCHANGED
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not validate_json(data, ['username', 'password']):
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({
        'status': 'success',
        'user': {
            'username': user.username,
            'category': user.category
        }
    }), 200

# YOUR ORIGINAL AQI DATA - UNCHANGED
aqidata = [250, 180, 130, 100, 110, 90, 80, 110, 140, 200, 350, 300]

# YOUR ORIGINAL AQI GET ROUTE - UNCHANGED
@app.route('/aqi/<int:index>', methods=['GET'])
def aqi(index):
    if not 1 <= index <= len(aqidata):
        return jsonify({'error': 'Invalid month index (1-12)'}), 400
    return jsonify({'month_index': index, 'aqi_value': aqidata[index - 1]})

# YOUR ORIGINAL PREDICT ROUTE - UNCHANGED
@app.route('/predict/<int:index>', methods=['POST'])
def get_aqi(index):
    data = request.get_json()
    if not validate_json(data, ['username']):
        return jsonify({'error': 'Username is required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 401

    if not 1 <= index <= len(aqidata):
        return jsonify({'error': 'Invalid month index (1-12)'}), 400

    aqi_value = aqidata[index - 1]

    try:
        new_request = AQIRequest(
            user_id=user.id,
            month_index=index,
            aqi_value=aqi_value
        )
        db.session.add(new_request)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
    # Fetch OpenWeatherMap Forecast (next available slot)
    forecast_aqi = None
    forecast_components = None

    try:
        ow_url = "http://api.openweathermap.org/data/2.5/air_pollution/forecast"
        ow_params = {
            'lat': 28.6139,
            'lon': 77.2090,
            'appid': os.getenv("OPENWEATHER_KEY")
        }
        ow_response = requests.get(ow_url, params=ow_params, timeout=10)
        ow_response.raise_for_status()

        forecast_data = ow_response.json().get('list', [])
        if forecast_data:
            first = forecast_data[0]
            forecast_aqi = first['main']['aqi']
            forecast_components = first['components']
    except Exception as e:
        print(f"OpenWeatherMap forecast error: {e}")

    # Dynamic solutions based on AQI value
    if aqi_value <= 50:
        solutions = {
            "Lung Disease/Asthma": "Air quality is safe. No special precautions are needed.",
            "Old Age": "Enjoy fresh air, but avoid dust exposure.",
            "Normal People": "No restrictions. Enjoy outdoor activities."
        }
    elif aqi_value <= 100:
        solutions = {
            "Lung Disease/Asthma": "Air quality is acceptable but be cautious with prolonged outdoor activities.",
            "Old Age": "Consider avoiding high-traffic areas.",
            "Normal People": "Outdoor activities are fine, but stay aware of air changes."
        }
    elif aqi_value <= 150:
        solutions = {
            "Lung Disease/Asthma": "Limit outdoor activities. Always carry an inhaler if needed.",
            "Old Age": "Reduce prolonged outdoor exposure.",
            "Normal People": "Most people are fine, but sensitive individuals should be cautious."
        }
    elif aqi_value <= 200:
        solutions = {
            "Lung Disease/Asthma": "Wear an N95 mask outdoors. Use an air purifier indoors.",
            "Old Age": "Stay indoors as much as possible and keep windows closed.",
            "Normal People": "Reduce outdoor activities and avoid prolonged exposure."
        }
    elif aqi_value <= 300:
        solutions = {
            "Lung Disease/Asthma": "Avoid going outside. If necessary, wear a mask and take medication as prescribed.",
            "Old Age": "Serious health risks. Stay inside with air purification if possible.",
            "Normal People": "Avoid strenuous outdoor activities. Consider working indoors."
        }
    else:
        solutions = {
            "Lung Disease/Asthma": "Severe risk! Stay indoors with an air purifier. Seek medical attention if breathing issues arise.",
            "Old Age": "Health emergency! Avoid going outside completely. Keep emergency contacts ready.",
            "Normal People": "Everyone should remain indoors and reduce physical activity."
        }
    
    return jsonify({
        'month_index': index,
        'aqi_value': aqi_value,
        'solution': solutions.get(user.category, 'No specific solution available.'),
        'forecast_aqi': forecast_aqi,
        'forecast_components': forecast_components
    })

# YOUR ORIGINAL HISTORY ROUTE - UNCHANGED
@app.route('/history', methods=['POST'])
def get_history():
    data = request.get_json()
    if not validate_json(data, ['username']):
        return jsonify({'error': 'Username is required'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 401

    history = AQIRequest.query.filter_by(user_id=user.id)\
                 .order_by(AQIRequest.timestamp.desc())\
                 .limit(10).all()
    
    history_data = [{
        'month_index': record.month_index,
        'aqi_value': record.aqi_value,
        'timestamp': record.timestamp.isoformat()
    } for record in history]

    return jsonify({'history': history_data})

# YOUR ORIGINAL DEBUG DATASET ROUTE - UNCHANGED
@app.route('/debug-dataset', methods=['GET'])
def debug_dataset():
    if df.empty:
        return jsonify({"error": "Dataset not loaded or empty"})
    return jsonify({"columns": df.columns.tolist(), "rows": len(df)})

# YOUR ORIGINAL VISUALIZATION ROUTE - UNCHANGED
@app.route('/run-notebook', methods=['POST'])
def get_aqi_graphs():
    try:
        data = request.get_json()
        if not data or 'month' not in data:
            return jsonify({"error": "Month parameter is required"}), 400

        month = int(data.get("month"))
        print(f"Received month for visualization: {month}")

        visualizations = {}
        
        # Generate visualizations
        if vis:  # Only if visualization module is available
            for viz_type, viz_func in [
                ("histogram", vis.plot_aqi_histogram),
                ("trend", vis.plot_aqi_trend),
                ("heatmap", vis.plot_aqi_heatmap),
                ("pollutants", vis.plot_pollutant_contribution)
            ]:
                try:
                    img = viz_func(month)
                    if img:
                        visualizations[viz_type] = img
                except Exception as e:
                    print(f"Error generating {viz_type} visualization: {e}")

        if not visualizations:
            return jsonify({"error": "No visualizations generated"}), 500

        return jsonify({
            "message": "Visualizations generated successfully",
            "visualizations": visualizations
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to generate visualizations: {str(e)}"}), 500

# Health check endpoint for Render
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)