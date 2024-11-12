from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import pymysql
import re
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_strong_secret_key'
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)

# MySQL 설정
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = '1234'
DB_NAME = 'flask_website_db'

# 데이터베이스 연결 함수
def get_db_connection():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, db=DB_NAME, charset='utf8')

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 기본 경로 설정
@app.route('/')
def home():
    return render_template('home.html')

# 회원가입 경로
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!")
            return redirect(url_for('register'))
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!")
            return redirect(url_for('register'))
        elif len(password) < 8:
            flash("Password must be at least 8 characters long!")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # SQL Injection 가능성 있는 코드
        query = f"SELECT * FROM users WHERE username = '{username}' OR email = '{email}'"
        cursor.execute(query)
        account = cursor.fetchone()
        
        if account:
            flash("Username or Email already exists!")
            return redirect(url_for('register'))
        
        hashed_password = password  # 단순화된 해싱 처리 (보안 취약점)
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{hashed_password}', '{email}')"
        cursor.execute(query)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

# 로그인 경로
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # SQL Injection 가능성 있는 코드
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        account = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not account:
            flash("Account does not exist or password is incorrect.")
            return redirect(url_for('login'))
        
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        flash(f"Hello, {session['username']}! You are logged in.")
        return redirect(url_for('home'))

    return render_template('login.html')

# 로그아웃 경로
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('home'))

# 마이페이지 경로
@app.route('/mypage')
@login_required
def mypage():
    return render_template('mypage.html', username=session['username'])

# 게시글 목록 조회 (Read)
@app.route('/posts')
def posts():
    query = request.args.get('query', '')

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    # SQL Injection 가능성 있는 코드
    if query:
        raw_query = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%' ORDER BY created_at DESC"
    else:
        raw_query = "SELECT * FROM posts ORDER BY created_at DESC"
    
    cursor.execute(raw_query)
    posts = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('posts.html', posts=posts)

# 게시글 작성 (Create)
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_private = 'is_private' in request.form
        user_id = session['id']

        file = request.files.get('file')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # SQL Injection 가능성 있는 코드
        query = f"INSERT INTO posts (title, content, is_private, filename, user_id) VALUES ('{title}', '{content}', {is_private}, '{filename}', {user_id})"
        cursor.execute(query)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Post created successfully!")
        return redirect(url_for('posts'))
    
    return render_template('create.html')

# 게시글 상세 조회 (Read)
@app.route('/post/<int:id>')
@login_required
def post(id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    # SQL Injection 가능성 있는 코드
    query = f"SELECT * FROM posts WHERE id = {id}"
    cursor.execute(query)
    post = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    if post is None:
        flash("Post not found!")
        return redirect(url_for('posts'))
    
    if post['is_private'] and post.get('user_id') and session['id'] != post['user_id']:
        flash("This is a private post.")
        return redirect(url_for('posts'))
    
    return render_template('post.html', post=post)

# 게시글 삭제 (Delete)
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # SQL Injection 가능성 있는 코드
    query = f"DELETE FROM posts WHERE id = {id}"
    cursor.execute(query)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Post deleted successfully!")
    return redirect(url_for('posts'))

# 파일 다운로드 경로
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
