from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_strong_secret_key'  # 강력한 난수로 secret_key 설정
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)  # CSRF 보호 활성화

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
        
        # 이메일 및 사용자명 검증
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!")
            return redirect(url_for('register'))
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!")
            return redirect(url_for('register'))
        elif len(password) < 8:  # 비밀번호 복잡도 검사
            flash("Password must be at least 8 characters long!")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
        account = cursor.fetchone()
        
        if account:
            flash("Username or Email already exists!")
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password, email) VALUES (%s, %s, %s)', 
                       (username, hashed_password, email))
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
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not account:
            flash("Account does not exist. Please register first.")
            return redirect(url_for('login'))
        
        if not check_password_hash(account['password'], password):
            flash("Incorrect password. Please try again.")
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
    session.clear()  # 세션 초기화
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
    
    if query:
        cursor.execute("SELECT * FROM posts WHERE title LIKE %s OR content LIKE %s ORDER BY created_at DESC", 
                       ('%' + query + '%', '%' + query + '%'))
    else:
        cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")

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
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (title, content) VALUES (%s, %s)', (title, content))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Post created successfully!")
        return redirect(url_for('posts'))
    
    return render_template('create.html')

# 게시글 상세 조회 (Read)
@app.route('/post/<int:id>')
def post(id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT * FROM posts WHERE id = %s', (id,))
    post = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if post is None:
        flash("Post not found!")
        return redirect(url_for('posts'))
    
    return render_template('post.html', post=post)

# 게시글 수정 (Update)
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        cursor.execute('UPDATE posts SET title = %s, content = %s WHERE id = %s', (title, content, id))
        conn.commit()
        flash("Post updated successfully!")
        return redirect(url_for('post', id=id))
    
    cursor.execute('SELECT * FROM posts WHERE id = %s', (id,))
    post = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if post is None:
        flash("Post not found!")
        return redirect(url_for('posts'))
    
    return render_template('edit.html', post=post)

# 게시글 삭제 (Delete)
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM posts WHERE id = %s', (id,))
    conn.commit()
    cursor.close()
    conn.close()
    
    flash("Post deleted successfully!")
    return redirect(url_for('posts'))

if __name__ == "__main__":
    app.run(port=5001, debug=True)
