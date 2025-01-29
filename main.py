from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Baza danych SQLite
app.secret_key = '810928430918309218'  # Klucz sesji
db = SQLAlchemy(app)

# Model Comment (Komentarze do postów)
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    entry_id = db.Column(db.Integer, db.ForeignKey('entry.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    entry = db.relationship('Entry', backref=db.backref('comments', lazy=True))

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Model Entry (Dane wprowadzone przez użytkownika)
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('entries', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Dodajemy timestamp

# Strona główna
@app.route('/')
def home():
    if 'user_id' in session:
        # Pobieramy wszystkie wpisy, niezależnie od użytkownika
        entries = Entry.query.all()
        return render_template('home.html', entries=entries)
    return redirect(url_for('login'))

# Usuwanie komentarza
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Znajdujemy komentarz po ID
    comment = Comment.query.get(comment_id)

    if not comment:
        return redirect(url_for('home'))  # Jeśli komentarz nie istnieje, przekierowujemy na stronę główną

    # Sprawdzamy, czy komentarz należy do zalogowanego użytkownika lub właściciela posta
    if comment.user_id == session['user_id'] or comment.entry.user_id == session['user_id']:
        db.session.delete(comment)  # Usuwamy komentarz
        db.session.commit()  # Zatwierdzamy zmiany w bazie danych

    return redirect(url_for('home'))  # Przekierowujemy z powrotem na stronę główną


# Edytowanie wpisu
@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Znajdujemy wpis po ID, tylko jeśli należy do zalogowanego użytkownika
    entry = Entry.query.filter_by(id=entry_id, user_id=session['user_id']).first()

    if not entry:
        return redirect(url_for('home'))  # Jeśli wpis nie istnieje lub nie należy do użytkownika, przekierowujemy na stronę główną

    if request.method == 'POST':
        # Zmieniamy zawartość wpisu
        entry.content = request.form['content']
        db.session.commit()  # Zatwierdzamy zmiany w bazie danych
        return redirect(url_for('home'))  # Przekierowujemy z powrotem na stronę główną

    return render_template('edit_entry.html', entry=entry)  # Zwracamy formularz do edytowania


# Dodawanie komnetarzy
@app.route('/comment/<int:entry_id>', methods=['POST'])
def add_comment(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = request.form['content']
    new_comment = Comment(content=content, user_id=session['user_id'], entry_id=entry_id)
    db.session.add(new_comment)
    db.session.commit()

    return redirect(url_for('home'))  # Przekierowanie z powrotem na stronę główną

# Usuwanie wpisu wraz z powiązanymi komentarzami
@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Znajdujemy wpis po ID i sprawdzamy, czy należy do zalogowanego użytkownika
    entry = Entry.query.filter_by(id=entry_id, user_id=session['user_id']).first()

    if entry:
        # Usuwamy powiązane komentarze
        Comment.query.filter_by(entry_id=entry.id).delete()

        # Usuwamy sam wpis
        db.session.delete(entry)
        db.session.commit()  # Zatwierdzamy zmiany w bazie danych

    return redirect(url_for('home'))  # Przekierowujemy z powrotem na stronę główną

# Strona logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        return 'Invalid username or password!'
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Sprawdzamy, czy użytkownik już istnieje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists! Please choose another one.'

        # Haszowanie hasła
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Po rejestracji logujemy użytkownika
        session['user_id'] = new_user.id
        return redirect(url_for('home'))

    return render_template('register.html')

# Profil użytkownika
@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()  # Zwraca 404 jeśli użytkownik nie istnieje
    entries = Entry.query.filter_by(user_id=user.id).all()  # Wszystkie wpisy użytkownika
    comments = Comment.query.filter_by(user_id=user.id).all()  # Wszystkie komentarze użytkownika
    return render_template('profile.html', user=user, entries=entries, comments=comments)

# Dodanie danych przez formularz
@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        new_entry = Entry(content=content, user_id=session['user_id'])
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add_entry.html')

# Wylogowanie
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():  # Tworzymy kontekst aplikacji
        db.create_all()  # Tworzymy tabele w bazie danych, jeśli jeszcze nie istnieją
    app.run(debug=True)
