from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import os
import bcrypt  # type: ignore
import pyotp  # type: ignore
import qrcode  # type: ignore
from io import BytesIO
import base64
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import send_from_directory, abort
import pymysql
pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # strong secret key

# MySQL Configuration (Using PyMySQL)
"""
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'tecsfrzo'
app.config['MYSQL_PASSWORD'] = 'yGtpiZDW2aQi'
app.config['MYSQL_DB'] = 'tecsfrzo_education_platform'
"""
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'education_platform'

# Initialize MySQL connection
connection = pymysql.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    database=app.config['MYSQL_DB'],
)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    # You will need to replace this with your actual user lookup logic
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            return User(user_id=result[0], username=result[1], role=result[2])
    return None

# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT user_id, username, role FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()
        if user:
            return User(user[0], user[1], user[2])
        return None
    except Exception as e:
        print(f"Error loading user: {str(e)}")
        return None


# Helper Functions
def generate_secret_key():
    return pyotp.random_base32()

def generate_totp_uri(username, secret_key):
    """
    Generate a TOTP URI for the QR code.
    :param username: The username of the user.
    :param secret_key: The secret key for 2FA.
    :return: A TOTP URI string.
    """
    return pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name="Education Platform")

def generate_qr_code(totp_uri):
    """
    Generate a QR code image from a TOTP URI.
    :param totp_uri: The TOTP URI.
    :return: A base64-encoded image string.
    """
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    # Create an image from the QR code
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert the image to a base64 string
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return img_str

def verify_otp(secret_key, otp):
    """
    Verify the OTP (One-Time Password) using the secret key.
    :param secret_key: The user's secret key.
    :param otp: The OTP entered by the user.
    :return: True if the OTP is valid, otherwise False.
    """
    totp = pyotp.TOTP(secret_key)
    return totp.verify(otp)


# Routes
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        try:
            # Hash the password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Generate a secret key for 2FA
            secret_key = generate_secret_key()

            # Generate a TOTP URI for the QR code
            totp_uri = generate_totp_uri(username, secret_key)

            # Generate the QR code image
            qr_code_img = generate_qr_code(totp_uri)

            # Insert user into the database
            with connection.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, secret_key) VALUES (%s, %s, %s, %s)",
                    (username, password_hash, role, secret_key)
                )
                connection.commit()

            # Redirect to a page to display the secret key and QR code
            return render_template('setup_2fa.html', secret_key=secret_key, qr_code_img=qr_code_img)

        except Exception as e:
            connection.rollback()
            return render_template('register.html', error=f"Error during registration: {str(e)}")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with connection.cursor() as cur:
                cur.execute("SELECT user_id, username, password_hash, role, secret_key, is_active FROM users WHERE username = %s", (username,))
                user = cur.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                if user[5] == 0:  # Check if the account is inactive
                    return render_template('login.html', error="Your account is inactive. Please contact the admin.")
                if user[4]:  # 2FA enabled
                    return redirect(url_for('verify_2fa', user_id=user[0]))
                else:
                    user_obj = User(user[0], user[1], user[3])
                    login_user(user_obj)
                    if user[3] == 'Admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user[3] == 'Teacher':
                        return redirect(url_for('teacher_dashboard'))
                    else:
                        return redirect(url_for('student_dashboard'))
            else:
                return render_template('login.html', error="Invalid username or password")
        except Exception as e:
            return render_template('login.html', error=f"An error occurred: {str(e)}")

    return render_template('login.html')


@app.route('/verify_2fa/<int:user_id>', methods=['GET', 'POST'])
def verify_2fa(user_id):
    if request.method == 'POST':
        otp = request.form['otp']

        try:
            with connection.cursor() as cur:
                cur.execute("SELECT secret_key, role FROM users WHERE user_id = %s", (user_id,))
                result = cur.fetchone()

            if result:
                secret_key, role = result

                # Verify the OTP
                if verify_otp(secret_key, otp):
                    user_obj = User(user_id, "", role)
                    login_user(user_obj)

                    # Redirect based on role
                    if role == 'Admin':
                        return redirect(url_for('admin_dashboard'))
                    elif role == 'Teacher':
                        return redirect(url_for('teacher_dashboard'))
                    elif role == 'Student':
                        return redirect(url_for('student_dashboard'))
                else:
                    return render_template('verify_2fa.html', error="Invalid OTP", user_id=user_id)
            else:
                return render_template('verify_2fa.html', error="User not found", user_id=user_id)
        except Exception as e:
            return render_template('verify_2fa.html', error=f"An error occurred: {str(e)}", user_id=user_id)
    
    return render_template('verify_2fa.html', user_id=user_id)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        # Implement password reset logic here
        return render_template('reset_password.html', message="Password reset instructions sent to your email")
    return render_template('reset_password.html')

# create manage_users to handle the logic for managing users
@app.route('/manage_users')
@login_required
def manage_users():
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT user_id, username, role, is_active FROM users")
            users = cur.fetchall()
        return render_template('manage_users.html', users=users)
    except Exception as e:
        return render_template('manage_users.html', error=f"An error occurred: {str(e)}")

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Role check to allow only admins
    if current_user.role != 'Admin':
        return redirect(url_for('home'))

    try:
        if request.method == 'POST':
            # Handle form submission to update the user
            username = request.form['username']
            role = request.form['role']

            with connection.cursor() as cur:
                cur.execute("UPDATE users SET username = %s, role = %s WHERE user_id = %s",
                            (username, role, user_id))
                connection.commit()

            return redirect(url_for('manage_users'))

        # Fetch the user's current details
        with connection.cursor() as cur:
            cur.execute("SELECT user_id, username, role FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()

        if user:
            return render_template('edit_user.html', user=user)
        else:
            return redirect(url_for('manage_users'))
    except Exception as e:
        return render_template('edit_user.html', error=f"An error occurred: {str(e)}")
    

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Role check to allow only admins
    if current_user.role != 'Admin':
        return redirect(url_for('home'))

    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            connection.commit()

        return redirect(url_for('manage_users'))
    except Exception as e:
        return redirect(url_for('manage_users', error=f"An error occurred: {str(e)}"))


@app.route('/delete_teacher/<int:teacher_id>', methods=['POST'])
@login_required
def delete_teacher(teacher_id):
    # Role check to allow only admins
    if current_user.role != 'Admin':
        return redirect(url_for('home'))

    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE teachers SET status = 0 WHERE tbl_id = %s", (teacher_id,))
            connection.commit()

        return redirect(url_for('admin_manage_teachers'))
    except Exception as e:
        return redirect(url_for('admin_manage_teachers', error=f"An error occurred: {str(e)}"))


# Admin route to manage all courses
@app.route('/admin/admin_manage_courses')
@login_required
def admin_manage_courses():
    if current_user.role != 'Admin':
        return redirect(url_for('teacher_dashboard'))

    try:
        # Fetch all courses from the database
        with connection.cursor() as cur:
            cur.execute("SELECT course_id, title, description, created_at FROM courses")
            courses = cur.fetchall()

        return render_template('admin_manage_courses.html', courses=courses)
    except Exception as e:
        return render_template('admin_manage_courses.html', error=f"An error occurred: {str(e)}")


@app.route('/admin/admin_manage_teachers')
@login_required
def admin_manage_teachers():
    if current_user.role != 'Admin':
        return render_template('admin_error.html', error="Unauthorized access")

    try:
        with connection.cursor() as cur:
            # Fetch all active teachers with their respective course titles
            cur.execute("""
                SELECT t.tbl_id, 
                       (SELECT u.username FROM users u WHERE u.user_id = t.teacher_id), 
                       (SELECT c.title FROM courses c WHERE c.course_id = t.course_id), 
                       t.created_at 
                FROM teachers t 
                WHERE t.status = 1
            """)
            teachers = cur.fetchall()

        return render_template('admin_manage_teachers.html', teachers=teachers)
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")

    
@app.route('/admin/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role != 'Admin':
        return render_template('admin_error.html', error="Unauthorized access")
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        try:
            with connection.cursor() as cur:
                cur.execute("INSERT INTO courses (title, description, teacher_id) VALUES (%s, %s, %s)", 
                            (title, description, current_user.id))
                connection.commit()

            return redirect(url_for('admin_manage_courses'))
        except Exception as e:
            return render_template('admin_error.html', error=f"An error occurred: {str(e)}")

    return render_template('add_course.html')


@app.route('/admin/add_teacher', methods=['GET', 'POST'])
@login_required
def add_teacher():
    if current_user.role != 'Admin':
        return render_template('admin_error.html', error="Unauthorized access")

    if request.method == 'POST':
        teacher = request.form['teacher']
        course = request.form['course']

        try:
            with connection.cursor() as cur:
                cur.execute("INSERT INTO teachers (teacher_id, course_id) VALUES (%s, %s)", 
                            (teacher, course))
                connection.commit()

            return redirect(url_for('admin_manage_teachers'))
        except Exception as e:
            return render_template('admin_error.html', error=f"An error occurred: {str(e)}")

    try:
        with connection.cursor() as cur:
            # Fetch teachers (teachers are users with the role 'Teacher')
            cur.execute("SELECT user_id, username FROM users WHERE role = 'Teacher'")
            teachers = cur.fetchall()

            # Fetch courses
            cur.execute("SELECT course_id, title FROM courses")
            courses = cur.fetchall()

        return render_template('add_teacher.html', teachers=teachers, courses=courses)
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")


@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    try:
        with connection.cursor() as cur:
            # Fetch the course details
            cur.execute("SELECT course_id, title, description, teacher_id FROM courses WHERE course_id = %s", (course_id,))
            course = cur.fetchone()

        if not course:
            return redirect(url_for('admin_manage_courses'))  # Course not found

        # Check if the current user is the teacher who created the course or an admin
        if current_user.role != 'Admin' and current_user.id != course[3]:  # course[3] is teacher_id
            return render_template('teacher_error.html', error="Unauthorized access")

        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']

            with connection.cursor() as cur:
                cur.execute("UPDATE courses SET title = %s, description = %s WHERE course_id = %s", 
                            (title, description, course_id))
                connection.commit()

            return redirect(url_for('admin_manage_courses'))

        return render_template('edit_course.html', course=course)
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")



@app.route('/view_course/<int:course_id>')
@login_required
def view_course(course_id):
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT title, description, created_at FROM courses WHERE course_id = %s", (course_id,))
            course = cur.fetchone()  # Fetch the course details

        if current_user.role != 'Teacher':
            return render_template('view_course.html', course=course)
        else:
            return render_template('teacher_view_course.html', course=course)
    except Exception as e:
        if current_user.role == 'Admin':
            return render_template('admin_error.html', error=f"An error occurred: {str(e)}")
        elif current_user.role == 'Teacher':
            return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")
        else:
            return render_template('student_error.html', error=f"An error occurred: {str(e)}")

    
@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    if current_user.role != 'Teacher':
        return redirect(url_for('admin_dashboard'))

    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM courses WHERE course_id = %s AND teacher_id = %s", 
                        (course_id, current_user.id))
            connection.commit()

        return redirect(url_for('teacher_manage_courses'))
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        return redirect(url_for('teacher_dashboard'))

    try:
        with connection.cursor() as cur:
            # Get total users count
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]

            # Get total courses count
            cur.execute("SELECT COUNT(*) FROM courses")
            total_courses = cur.fetchone()[0]

            # Get total teachers assigned count
            cur.execute("SELECT COUNT(*) FROM teachers WHERE status = 1")
            total_teachers = cur.fetchone()[0]

            # Uncomment these lines if active sessions and recent activities tracking is needed
            # cur.execute("SELECT COUNT(*) FROM users WHERE last_login >= NOW() - INTERVAL 30 MINUTE")
            # active_sessions = cur.fetchone()[0]

            # cur.execute("SELECT message FROM activity_log ORDER BY created_at DESC LIMIT 5")
            # recent_activities = [row[0] for row in cur.fetchall()]

        return render_template('admin_dashboard.html', 
                               total_users=total_users, 
                               total_courses=total_courses, 
                               total_teachers=total_teachers)
                               # active_sessions=active_sessions,
                               # recent_activities=recent_activities)
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# Define the activate_user and deactivate_user Routes
@app.route('/activate_user/<int:user_id>', methods=['POST'])
@login_required
def activate_user(user_id):
    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE users SET is_active = 1 WHERE user_id = %s", (user_id,))
            connection.commit()

        return redirect(url_for('manage_users'))
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")


@app.route('/deactivate_user/<int:user_id>', methods=['POST'])
@login_required
def deactivate_user(user_id):
    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE users SET is_active = 0 WHERE user_id = %s", (user_id,))
            connection.commit()

        return redirect(url_for('manage_users'))
    except Exception as e:
        return render_template('admin_error.html', error=f"An error occurred: {str(e)}")


# Teacher Dashboard
@app.route('/teacher_dashboard')
@login_required
def teacher_dashboard():
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM teachers WHERE teacher_id = %s AND status = 1", (current_user.id,))
            total_courses = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM submissions WHERE course_id IN (SELECT course_id FROM courses WHERE teacher_id = %s) AND grade IS NULL", (current_user.id,))
            pending_submissions = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT student_id) FROM enrollments WHERE course_id IN (SELECT course_id FROM courses WHERE teacher_id = %s)", (current_user.id,))
            total_students = cur.fetchone()[0]

        return render_template('teacher_dashboard.html', total_courses=total_courses, pending_submissions=pending_submissions, total_students=total_students)
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


# Teacher route to manage their own courses
@app.route('/teacher/manage_courses')
@login_required
def teacher_manage_courses():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    try:
        with connection.cursor() as cur:
            cur.execute("SELECT t.course_id, (SELECT c.title FROM courses c WHERE c.course_id = t.course_id), (SELECT c.description FROM courses c WHERE c.course_id = t.course_id) FROM teachers t WHERE t.teacher_id = %s AND t.status = 1", (current_user.id,))
            courses = cur.fetchall()

        return render_template('teacher_manage_courses.html', courses=courses)
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


# Teacher route to manage students
@app.route('/teacher/manage_students')
@login_required
def teacher_manage_students():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    try:
        with connection.cursor() as cur:
            cur.execute("SELECT t.course_id, (SELECT c.title FROM courses c WHERE c.course_id = t.course_id) FROM teachers t WHERE t.teacher_id = %s AND t.status = 1", (current_user.id,))
            courses = cur.fetchall()

        return render_template('teacher_manage_students.html', courses=courses)
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


# Fetch students
@app.route('/teacher/get_students')
@login_required
def get_students():
    course_id = request.args.get('course_id')

    try:
        with connection.cursor() as cur:
            # Fetch all students
            cur.execute("SELECT user_id, username, email FROM users WHERE role = 'Student'")
            students = cur.fetchall()

            # Fetch enrolled students for the selected course
            cur.execute("SELECT student_id FROM enrollments WHERE course_id = %s", (course_id,))
            enrolled_students = {row[0] for row in cur.fetchall()}

        # Prepare response data
        student_data = []
        for student in students:
            student_data.append({
                "user_id": student[0],
                "username": student[1],
                "email": student[2],
                "enrolled": student[0] in enrolled_students
            })

        return jsonify({"students": student_data})
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


# Add a route to handle enrollment/unenrollment of students
@app.route('/teacher/enroll_students', methods=['POST'])
@login_required
def enroll_students():
    course_id = request.form['course_id']
    student_ids = request.form.getlist('student_ids')

    try:
        with connection.cursor() as cur:
            # Remove all existing enrollments for the course
            cur.execute("DELETE FROM enrollments WHERE course_id = %s", (course_id,))

            # Add new enrollments
            for student_id in student_ids:
                cur.execute("INSERT INTO enrollments (student_id, course_id) VALUES (%s, %s)",
                            (student_id, course_id))

            connection.commit()

        flash('Enrollments updated successfully!', 'success')
        return redirect(url_for('teacher_manage_students'))
    except Exception as e:
        return render_template('teacher_error.html', error=f"An error occurred: {str(e)}")


# Teacher route to update profile
@app.route('/teacher/profile', methods=['GET', 'POST'])
@login_required
def teacher_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        try:
            # Update the user's profile in the database
            with connection.cursor() as cur:
                cur.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                            (username, email, current_user.id))
                connection.commit()

            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash(f"An error occurred: {str(e)}", 'error')

        return redirect(url_for('teacher_profile'))

    return render_template('teacher_profile.html')


# Change password
@app.route('/teacher/change_password', methods=['POST'])
@login_required
def teacher_change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    try:
        with connection.cursor() as cur:
            # Verify the current password
            cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (current_user.id,))
            user = cur.fetchone()

        if user and bcrypt.checkpw(current_password.encode('utf-8'), user[0].encode('utf-8')):
            if new_password == confirm_password:
                # Hash the new password
                new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                # Update the password in the database
                with connection.cursor() as cur:
                    cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s",
                                (new_password_hash, current_user.id))
                    connection.commit()

                flash('Password changed successfully!', 'success')
            else:
                flash('New passwords do not match.', 'error')
        else:
            flash('Current password is incorrect.', 'error')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('teacher_profile'))


# Enable 2FA
@app.route('/enable_2fa')
@login_required
def enable_2fa():
    try:
        # Generate a new secret key for 2FA
        secret_key = generate_secret_key()

        # Update the user's secret key in the database
        with connection.cursor() as cur:
            cur.execute("UPDATE users SET secret_key = %s WHERE user_id = %s", (secret_key, current_user.id))
            connection.commit()

        flash('2FA enabled successfully!', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('teacher_profile'))


# Disable 2FA
@app.route('/disable_2fa')
@login_required
def disable_2fa():
    try:
        # Remove the user's secret key from the database
        with connection.cursor() as cur:
            cur.execute("UPDATE users SET secret_key = NULL WHERE user_id = %s", (current_user.id,))
            connection.commit()

        flash('2FA disabled successfully!', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('teacher_profile'))


# Route to fetch submissions for the teacher's courses:
@app.route('/view_submissions')
@login_required
def view_submissions():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    try:
        # Fetch submissions for the teacher's courses
        with connection.cursor() as cur:
            cur.execute("""
                SELECT s.submission_id, u.username, c.title, s.submission_date, s.grade, s.feedback
                FROM submissions s
                JOIN users u ON s.student_id = u.user_id
                JOIN courses c ON s.course_id = c.course_id
                JOIN teachers t ON s.course_id = t.course_id
                WHERE t.teacher_id = %s
            """, (current_user.id,))
            submissions = cur.fetchall()

        return render_template('view_submissions.html', submissions=submissions)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect(url_for('teacher_dashboard'))


# Route to handle grading submission
@app.route('/grade_submission/<int:submission_id>', methods=['POST'])
@login_required
def grade_submission(submission_id):
    grade = request.form['grade']

    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE submissions SET grade = %s WHERE submission_id = %s", (grade, submission_id))
            connection.commit()

        flash('Grade updated successfully!', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('view_submissions'))


# Route to handle adding feedback
@app.route('/add_feedback/<int:submission_id>', methods=['POST'])
@login_required
def add_feedback(submission_id):
    feedback = request.form['feedback']

    try:
        with connection.cursor() as cur:
            cur.execute("UPDATE submissions SET feedback = %s WHERE submission_id = %s", (feedback, submission_id))
            connection.commit()

        flash('Feedback updated successfully!', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('view_submissions'))


# Route to view detailed information about a submission
@app.route('/view_submission_details/<int:submission_id>')
@login_required
def view_submission_details(submission_id):
    try:
        with connection.cursor() as cur:
            cur.execute("""
                SELECT s.submission_id, u.username, c.title, s.submission_date, s.grade, s.feedback, s.file_path
                FROM submissions s
                JOIN users u ON s.student_id = u.user_id
                JOIN courses c ON s.course_id = c.course_id
                WHERE s.submission_id = %s
            """, (submission_id,))
            submission = cur.fetchone()

        if not submission:
            flash('Submission not found.', 'error')
            return redirect(url_for('view_submissions'))

        return render_template('view_submission_details.html', submission=submission)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect(url_for('view_submissions'))


# This route allows teachers to upload assignments for their courses.

# Configure upload folder for assignments
import os
from flask import send_from_directory

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads/assignments')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/teacher/upload_assignment', methods=['GET', 'POST'])
@login_required
def upload_assignment():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    if request.method == 'POST':
        course_id = request.form['course_id']
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        file = request.files['file']

        if file and allowed_file(file.filename):
            try:
                # Save the file with a unique name
                filename = f"{current_user.id}_{course_id}_{file.filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Insert assignment into the database
                with connection.cursor() as cur:
                    cur.execute("""
                        INSERT INTO assignments (course_id, title, description, due_date, file_path)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (course_id, title, description, due_date, file_path))
                    connection.commit()

                flash('Assignment uploaded successfully!', 'success')
            except Exception as e:
                flash(f"An error occurred while uploading the assignment: {str(e)}", 'error')
        else:
            flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')

        return redirect(url_for('upload_assignment'))

    # Fetch courses taught by the current teacher
    with connection.cursor() as cur:
        cur.execute("SELECT course_id, title FROM courses WHERE teacher_id = %s", (current_user.id,))
        courses = cur.fetchall()

    # Fetch assignments for the teacher's courses
    with connection.cursor() as cur:
        cur.execute("""
            SELECT a.assignment_id, c.title, a.title, a.description, a.due_date, a.file_path
            FROM assignments a
            JOIN courses c ON a.course_id = c.course_id
            WHERE c.teacher_id = %s
        """, (current_user.id,))
        assignments = cur.fetchall()

    return render_template('teacher_upload_assignment.html', courses=courses, assignments=assignments)


# Route to allow teachers to download assignment files
# Download submission route
@app.route('/download_submission/<filename>')
@login_required
def download_submission(filename):
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    # Check if the file exists in the uploads directory
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        abort(404)

    # Serve the file using send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Download assignment route
@app.route('/download_assignment/<filename>')
@login_required
def download_assignment(filename):
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))

    # Check if the file exists in the uploads directory
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        abort(404)

    # Serve the file using send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# Error Handlers in Flask
# All errors are handled here 
# 

# Handle 404 (Page Not Found) errors
# Error handler for 404 (Page Not Found)
@app.errorhandler(404)
def page_not_found(error):
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return render_template('admin_error.html'), 404
        elif current_user.role == 'Teacher':
            return render_template('teacher_error.html'), 404
        elif current_user.role == 'Student':
            return render_template('student_error.html'), 404
    else:
        return render_template('generic_error.html'), 404  # Fallback for unauthenticated users


# Handle 403 (Forbidden) errors
@app.errorhandler(403)
def forbidden(error):
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return render_template('admin_error.html'), 403
        elif current_user.role == 'Teacher':
            return render_template('teacher_error.html'), 403
        elif current_user.role == 'Student':
            return render_template('student_error.html'), 403
    else:
        return render_template('generic_error.html'), 403  # Fallback for unauthenticated users


# Handle 500 (Internal Server Error) errors
@app.errorhandler(500)
def internal_server_error(error):
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return render_template('admin_error.html'), 500
        elif current_user.role == 'Teacher':
            return render_template('teacher_error.html'), 500
        elif current_user.role == 'Student':
            return render_template('student_error.html'), 500
    else:
        return render_template('generic_error.html'), 500  # Fallback for unauthenticated users


# route to handle view submission downloads

@app.errorhandler(500)
def internal_server_error(error):
    if current_user.is_authenticated:
        if current_user.role == 'Admin':
            return render_template('admin_error.html'), 500
        elif current_user.role == 'Teacher':
            return render_template('teacher_error.html'), 500
        elif current_user.role == 'Student':
            return render_template('student_error.html'), 500
    else:
        return render_template('generic_error.html'), 500  # Fallback for unauthenticated users

"""
The student Module is a separate module that contains routes and views for the student dashboard, courses, submissions, and profile.
The student module will be protected by the login_required decorator, so only authenticated users can access the student dashboard.
"""

# students Dashboard
@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch quick stats for the student
    cur = connection.cursor()

    # Get total enrolled courses
    cur.execute("SELECT COUNT(*) FROM enrollments WHERE student_id = %s", (current_user.id,))
    total_courses = cur.fetchone()[0]

    # Get pending submissions (assignments not yet submitted)
    cur.execute("""
        SELECT COUNT(*)
        FROM assignments a
        JOIN enrollments e ON a.course_id = e.course_id
        WHERE e.student_id = %s
        AND a.assignment_id NOT IN (
            SELECT s.assignment_id FROM submissions s WHERE s.student_id = %s
        )
    """, (current_user.id, current_user.id))
    pending_submissions = cur.fetchone()[0]

    # Get recent grades (limit to 5 latest graded submissions)
    cur.execute("""
        SELECT c.title, s.grade
        FROM submissions s
        JOIN courses c ON s.course_id = c.course_id
        WHERE s.student_id = %s AND s.grade IS NOT NULL
        ORDER BY s.submission_date DESC
        LIMIT 5
    """, (current_user.id,))
    recent_grades = cur.fetchall()

    cur.close()

    return render_template('student_dashboard.html', total_courses=total_courses, pending_submissions=pending_submissions, recent_grades=recent_grades)

# List all courses the student is enrolled in
@app.route('/student_courses')
@login_required
def student_courses():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch enrolled courses
    cur = connection.cursor()
    cur.execute("""
        SELECT c.course_id, c.title, c.description
        FROM courses c
        JOIN enrollments e ON c.course_id = e.course_id
        WHERE e.student_id = %s
    """, (current_user.id,))
    courses = cur.fetchall()
    cur.close()

    return render_template('student_courses.html', courses=courses)

# View submissions and grades for a student
@app.route('/student_submissions')
@login_required
def student_submissions():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    cur = connection.cursor()

    # Fetch submissions and grades for the student
    cur.execute("""
        SELECT s.submission_id, c.title, s.submission_date, s.grade, s.feedback
        FROM submissions s
        JOIN courses c ON s.course_id = c.course_id
        WHERE s.student_id = %s
    """, (current_user.id,))
    submissions = cur.fetchall()

    # Fetch enrolled courses and assignments for those courses
    cur.execute("""
        SELECT c.course_id, c.title
        FROM courses c
        JOIN enrollments e ON c.course_id = e.course_id
        WHERE e.student_id = %s
    """, (current_user.id,))
    enrolled_courses = cur.fetchall()

    cur.execute("""
        SELECT a.assignment_id, a.title, c.title AS course_title
        FROM assignments a
        JOIN courses c ON a.course_id = c.course_id
        WHERE a.course_id IN (
            SELECT e.course_id FROM enrollments e WHERE e.student_id = %s
        )
    """, (current_user.id,))
    assignments = cur.fetchall()

    cur.close()

    return render_template('student_submissions.html', submissions=submissions, enrolled_courses=enrolled_courses, assignments=assignments)


# This page allows students to update their profile information.
import uuid
from werkzeug.utils import secure_filename

# Student profile update
@app.route('/student_profile', methods=['GET', 'POST'])
@login_required
def student_profile():
    if current_user.role != 'Student':
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        # Validate the inputs
        if not username or not email:
            flash('Username and Email are required.', 'error')
            return redirect(url_for('student_profile'))

        try:
            # Update the student's profile in the database
            cur = connection.cursor()
            cur.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                        (username, email, current_user.id))
            connection.commit()
            cur.close()

            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'error')

        return redirect(url_for('student_profile'))

    return render_template('student_profile.html')

# Submit assignment
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/submit_assignment', methods=['POST'])
@login_required
def submit_assignment():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    course_id = request.form['course_id']
    assignment_id = request.form['assignment_id']
    file = request.files['file']

    if file and allowed_file(file.filename):
        # Secure the filename
        original_filename = secure_filename(file.filename)
        filename = f"{current_user.id}_{assignment_id}_{uuid.uuid4().hex}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            # Save the file
            file.save(file_path)

            # Insert submission into the database
            cur = connection.cursor()
            cur.execute("""
                INSERT INTO submissions (student_id, course_id, assignment_id, file_path)
                VALUES (%s, %s, %s, %s)
            """, (current_user.id, course_id, assignment_id, file_path))
            connection.commit()
            cur.close()

            flash('Assignment submitted successfully!', 'success')
        except Exception as e:
            flash(f'Error submitting assignment: {str(e)}', 'error')
    else:
        flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')

    return redirect(url_for('student_submissions'))


if __name__ == '__main__':
    app.run(debug=True)