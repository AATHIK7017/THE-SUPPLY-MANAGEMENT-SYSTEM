from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# SQLite Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Admin')

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    stock = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(20))
    threshold = db.Column(db.Integer, default=5)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    requested_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# Initialize DB and default admin
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin123'), role='Admin')
        db.session.add(admin_user)
        db.session.commit()

# Helper decorator
def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Routes
@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    total_items = Item.query.count()
    low_stock = Item.query.filter(Item.stock <= Item.threshold).count()
    total_requests = Request.query.count()
    recent_transactions = Request.query.order_by(Request.id.desc()).limit(5).count()
    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           total_items=total_items,
                           low_stock=low_stock,
                           total_requests=total_requests,
                           recent_transactions=recent_transactions)

# Items routes
@app.route('/items')
@login_required
def items_page():
    items = Item.query.all()
    return render_template('items.html', items=items,
                           username=session['username'],
                           role=session['role'])

@app.route('/add_item', methods=['POST'])
@login_required
def add_item():
    if session['role'] not in ['Admin','Quartermaster']:
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    item = Item(
        name=request.form['name'],
        category=request.form['category'],
        stock=int(request.form['stock']),
        unit=request.form['unit'],
        threshold=int(request.form['threshold'])
    )
    db.session.add(item)
    db.session.commit()
    return redirect(url_for('items_page'))

@app.route('/update_item/<int:item_id>', methods=['POST'])
@login_required
def update_item(item_id):
    if session['role'] not in ['Admin','Quartermaster']:
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    item = Item.query.get_or_404(item_id)
    item.name = request.form['name']
    item.category = request.form['category']
    item.stock = int(request.form['stock'])
    item.unit = request.form['unit']
    item.threshold = int(request.form['threshold'])
    db.session.commit()
    return redirect(url_for('items_page'))

@app.route('/delete_item/<int:item_id>')
@login_required
def delete_item(item_id):
    if session['role'] not in ['Admin','Quartermaster']:
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('items_page'))

# Requests routes
@app.route('/requests', methods=['GET','POST'])
@login_required
def requests_page():
    user = User.query.get(session['user_id'])
    if request.method == 'POST' and user.role == 'Scout':
        new_req = Request(
            item_id=int(request.form['item_id']),
            quantity=int(request.form['quantity']),
            requested_by=user.id
        )
        db.session.add(new_req)
        db.session.commit()
        flash("Request submitted successfully!", "success")
        return redirect(url_for('requests_page'))

    if user.role in ['Quartermaster','Admin']:
        requests_list = Request.query.order_by(Request.id.desc()).all()
    else:
        requests_list = Request.query.filter_by(requested_by=user.id).order_by(Request.id.desc()).all()
    return render_template('requests.html', requests=requests_list, user=user)

@app.route('/update_request/<int:req_id>', methods=['POST'])
@login_required
def update_request(req_id):
    if session['role'] not in ['Quartermaster','Admin']:
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    req = Request.query.get_or_404(req_id)
    req.status = request.form['status']
    db.session.commit()
    flash("Request updated successfully!", "success")
    return redirect(url_for('requests_page'))

# Manage users (Admin only)
@app.route('/manage_users')
@login_required
def manage_users():
    if session['role'] != 'Admin':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    users_list = User.query.all()
    return render_template('manage_users.html', users=users_list,
                           username=session['username'], role=session['role'])

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if session['role'] != 'Admin':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    if User.query.filter_by(username=username).first():
        flash("Username already exists!", "warning")
        return redirect(url_for('manage_users'))
    new_user = User(username=username, password=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    flash("User added successfully!", "success")
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if session['role'] != 'Admin':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("Cannot delete default admin!", "warning")
        return redirect(url_for('manage_users'))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for('manage_users'))

# Alerts page
@app.route('/alerts')
@login_required
def alerts_page():
    low_items = Item.query.filter(Item.stock <= Item.threshold).all()
    return render_template('alerts.html', low_items=low_items,
                           username=session['username'], role=session['role'])

# Analytics page
@app.route('/analytics')
@login_required
def analytics_page():
    items = Item.query.all()
    low_stock_items = Item.query.filter(Item.stock <= Item.threshold).all()
    requests_list = Request.query.all()
    return render_template('analytics.html',
                           items_labels=[i.name for i in items],
                           items_data=[i.stock for i in items],
                           low_stock_labels=[i.name for i in low_stock_items],
                           low_stock_data=[i.stock for i in low_stock_items],
                           requests_labels=[r.id for r in requests_list],
                           requests_data=[r.quantity for r in requests_list],
                           username=session['username'], role=session['role'])

if __name__ == '__main__':
    app.run(debug=True)
