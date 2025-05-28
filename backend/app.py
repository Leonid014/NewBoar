from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    class_ = db.Column(db.String(20), nullable=False)
    contacts = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(120))
    interests = db.relationship('Interest', backref='user', lazy='dynamic')
    skills = db.relationship('Skill', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class InterestCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    interests = db.relationship('Interest', backref='category', lazy=True)

class SkillCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    skills = db.relationship('Skill', backref='category', lazy=True)

class Interest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('interest_category.id'), nullable=False)

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('skill_category.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    name = StringField('Имя', validators=[DataRequired()])
    class_ = StringField('Класс', validators=[DataRequired()])
    contacts = StringField('Контакты', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Этот email уже используется.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class ProfileForm(FlaskForm):
    name = StringField('Имя', validators=[DataRequired()])
    class_ = StringField('Класс', validators=[DataRequired()])
    contacts = StringField('Контакты', validators=[DataRequired()])
    avatar = FileField('Аватар')
    submit = SubmitField('Сохранить')

class InterestForm(FlaskForm):
    name = StringField('Интерес', validators=[DataRequired()])
    category_id = SelectField('Категория', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Добавить')

class SkillForm(FlaskForm):
    name = StringField('Навык', validators=[DataRequired()])
    category_id = SelectField('Категория', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Добавить')

class InterestCategoryForm(FlaskForm):
    name = StringField('Название категории', validators=[DataRequired()])
    submit = SubmitField('Добавить категорию')

class SkillCategoryForm(FlaskForm):
    name = StringField('Название категории', validators=[DataRequired()])
    submit = SubmitField('Добавить категорию')

class SearchForm(FlaskForm):
    search_query = StringField('Поиск')
    class_filter = SelectField('Класс', coerce=str, validators=[])
    interest_category_filter = SelectField('Категория интересов', coerce=str, validators=[])
    skill_category_filter = SelectField('Категория навыков', coerce=str, validators=[])
    submit = SubmitField('Найти')

    def __init__(self, *args, **kwargs):
        super(SearchForm, self).__init__(*args, **kwargs)
        self.class_filter.choices = [('', 'Все классы')] + [(c.class_, c.class_) for c in db.session.query(User.class_).distinct()]
        self.interest_category_filter.choices = [('', 'Все категории')] + [(str(c.id), c.name) for c in InterestCategory.query.all()]
        self.skill_category_filter.choices = [('', 'Все категории')] + [(str(c.id), c.name) for c in SkillCategory.query.all()]

@app.route('/')
def index():
    theme = request.cookies.get('theme', 'light')
    users = User.query.limit(6).all()
    total_users = User.query.count()
    return render_template('index.html', 
                         theme=theme, 
                         users=users,
                         total_users=total_users)

@app.route('/search', methods=['GET', 'POST'])
def search():
    theme = request.cookies.get('theme', 'light')
    form = SearchForm()
    
    # Заполняем choices для фильтров при GET-запросе
    if request.method == 'GET':
        form.class_filter.choices = [('', 'Все классы')] + [(c.class_, c.class_) for c in db.session.query(User.class_).distinct()]
        form.interest_category_filter.choices = [('', 'Все категории')] + [(str(c.id), c.name) for c in InterestCategory.query.all()]
        form.skill_category_filter.choices = [('', 'Все категории')] + [(str(c.id), c.name) for c in SkillCategory.query.all()]
    
    query = User.query
    
    if request.method == 'POST':
        # Получаем данные из формы
        search_query = request.form.get('search_query', '').strip()
        class_filter = request.form.get('class_filter', '')
        interest_category_filter = request.form.get('interest_category_filter', '')
        skill_category_filter = request.form.get('skill_category_filter', '')
        
        # Применяем фильтры
        if search_query:
            query = query.filter(
                User.name.ilike(f"%{search_query}%") |
                User.class_.ilike(f"%{search_query}%")
            )
        
        if class_filter:
            query = query.filter(User.class_ == class_filter)
        
        if interest_category_filter and interest_category_filter != '':
            try:
                query = query.join(Interest).filter(Interest.category_id == int(interest_category_filter))
            except (ValueError, TypeError):
                pass
        
        if skill_category_filter and skill_category_filter != '':
            try:
                query = query.join(Skill).filter(Skill.category_id == int(skill_category_filter))
            except (ValueError, TypeError):
                pass
    
    users = query.distinct().all()
    return render_template('search.html', 
                         theme=theme, 
                         users=users,
                         form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            name=form.name.data,
            class_=form.class_.data,
            contacts=form.contacts.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный email или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('index'))

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    theme = request.cookies.get('theme', 'light')
    user = User.query.get_or_404(user_id)
    
    # Явно загружаем связанные данные
    user = User.query.options(
        db.joinedload(User.interests).joinedload(Interest.category),
        db.joinedload(User.skills).joinedload(Skill.category)
    ).get(user_id)
    
    interest_categories = InterestCategory.query.all()
    skill_categories = SkillCategory.query.all()
    
    interest_form = InterestForm()
    interest_form.category_id.choices = [(c.id, c.name) for c in interest_categories]
    
    skill_form = SkillForm()
    skill_form.category_id.choices = [(c.id, c.name) for c in skill_categories]
    
    return render_template('profile.html', 
                         theme=theme, 
                         user=user,
                         interest_categories=interest_categories,
                         skill_categories=skill_categories,
                         interest_form=interest_form,
                         skill_form=skill_form)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    theme = request.cookies.get('theme', 'light')
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.class_ = form.class_.data
        current_user.contacts = form.contacts.data
        if form.avatar.data:
            filename = secure_filename(form.avatar.data.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.avatar.data.save(filepath)
            current_user.avatar = filename
        db.session.commit()
        flash('Профиль обновлен!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))
    return render_template('edit_profile.html', form=form, theme=theme)

@app.route('/add_interest', methods=['POST'])
@login_required
def add_interest():
    form = InterestForm()
    form.category_id.choices = [(c.id, c.name) for c in InterestCategory.query.all()]
    if form.validate_on_submit():
        try:
            interest = Interest(
                user_id=current_user.id,
                name=form.name.data,
                category_id=form.category_id.data
            )
            db.session.add(interest)
            db.session.commit()
            flash('Интерес добавлен!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при добавлении интереса', 'danger')
            app.logger.error(f"Error adding interest: {e}")
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/add_skill', methods=['POST'])
@login_required
def add_skill():
    form = SkillForm()
    form.category_id.choices = [(c.id, c.name) for c in SkillCategory.query.all()]
    if form.validate_on_submit():
        skill = Skill(
            user_id=current_user.id,
            name=form.name.data,
            category_id=form.category_id.data
        )
        db.session.add(skill)
        db.session.commit()
        flash('Навык добавлен!', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/add_interest_category', methods=['POST'])
@login_required
def add_interest_category():
    form = InterestCategoryForm()
    if form.validate_on_submit():
        existing = InterestCategory.query.filter_by(name=form.name.data).first()
        if existing:
            flash('Категория с таким названием уже существует', 'info')
        else:
            category = InterestCategory(name=form.name.data)
            db.session.add(category)
            db.session.commit()
            flash('Категория интересов добавлена!', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/add_skill_category', methods=['POST'])
@login_required
def add_skill_category():
    form = SkillCategoryForm()
    if form.validate_on_submit():
        existing = SkillCategory.query.filter_by(name=form.name.data).first()
        if existing:
            flash('Категория с таким названием уже существует', 'info')
        else:
            category = SkillCategory(name=form.name.data)
            db.session.add(category)
            db.session.commit()
            flash('Категория навыков добавлена!', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/delete_interest/<int:id>')
@login_required
def delete_interest(id):
    interest = Interest.query.get_or_404(id)
    if interest.user_id == current_user.id:
        db.session.delete(interest)
        db.session.commit()
        flash('Интерес удален', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/delete_skill/<int:id>')
@login_required
def delete_skill(id):
    skill = Skill.query.get_or_404(id)
    if skill.user_id == current_user.id:
        db.session.delete(skill)
        db.session.commit()
        flash('Навык удален', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/delete_interest_category/<int:id>')
@login_required
def delete_interest_category(id):
    category = InterestCategory.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    flash('Категория интересов удалена', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/delete_skill_category/<int:id>')
@login_required
def delete_skill_category(id):
    category = SkillCategory.query.get_or_404(id)
    db.session.delete(category)
    db.session.commit()
    flash('Категория навыков удалена', 'success')
    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/toggle-theme')
def toggle_theme():
    theme = request.cookies.get('theme', 'light')
    new_theme = 'dark' if theme == 'light' else 'light'
    response = make_response(redirect(request.referrer or url_for('index')))
    response.set_cookie('theme', new_theme)
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)

