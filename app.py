from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash  # type: ignore # Add flash here
from flask_mysqldb import MySQL # type: ignore
import os
import bcrypt # type: ignore
import pyotp # type: ignore
import qrcode # type: ignore
from io import BytesIO
import base64
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required # type: ignore
from flask_login import current_user # type: ignore
from flask import render_template # type: ignore
from flask import send_from_directory # type: ignore

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure key

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'education_platform'
mysql = MySQL(app)

"""
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'tecsfrzo'
app.config['MYSQL_PASSWORD'] = 'yGtpiZDW2aQi'
app.config['MYSQL_DB'] = 'tecsfrzo_education_platform'
mysql = MySQL(app)
"""
# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)

# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, role FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    if user:
        return User(user[0], user[1], user[2])
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
            with mysql.connection.cursor() as cur:
                cur.execute("INSERT INTO users (username, password_hash, role, secret_key) VALUES (%s, %s, %s, %s)",
                            (username, password_hash, role, secret_key))
                mysql.connection.commit()

            # Redirect to a page to display the secret key and QR code
            return render_template('setup_2fa.html', secret_key=secret_key, qr_code_img=qr_code_img)

        except Exception as e:
            mysql.connection.rollback()
            return render_template('register.html', error=str(e))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, username, password_hash, role, secret_key, is_active FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

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
    return render_template('login.html')

@app.route('/verify_2fa/<int:user_id>', methods=['GET', 'POST'])
def verify_2fa(user_id):
    if request.method == 'POST':
        otp = request.form['otp']

        # Fetch the user's secret key and role
        cur = mysql.connection.cursor()
        cur.execute("SELECT secret_key, role FROM users WHERE user_id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()

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
    # Fetch all users from the database
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, role, is_active FROM users")
    users = cur.fetchall()
    cur.close()

    # Render the manage_users template with the list of users
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if request.method == 'POST':
        # Handle form submission to update the user
        username = request.form['username']
        role = request.form['role']

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET username = %s, role = %s WHERE user_id = %s",
                    (username, role, user_id))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('manage_users'))

    # Fetch the user's current details
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, role FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if user:
        return render_template('edit_user.html', user=user)
    else:
        return redirect(url_for('manage_users'))
    

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Delete the user from the database
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('manage_users'))

@app.route('/delete_teacher/<int:teacher_id>', methods=['POST'])
@login_required
def delete_teacher(teacher_id):
    # Delete the teacher from the database
    cur = mysql.connection.cursor()
    cur.execute("UPDATE `teachers` SET `status` = 0 WHERE tbl_id = %s", (teacher_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('admin_manage_teachers'))

# Admin route to manage all courses
@app.route('/admin/admin_manage_courses')
@login_required
def admin_manage_courses():
    # if current_user.role != 'Admin':
        # return redirect(url_for('teacher_dashboard'))
    
    # Fetch all courses from the database
    cur = mysql.connection.cursor()
    cur.execute("SELECT course_id, title, description, created_at FROM courses")
    courses = cur.fetchall()
    cur.close()

    return render_template('admin_manage_courses.html', courses=courses)

@app.route('/admin/admin_manage_teachers')
@login_required
def admin_manage_teachers():
     if current_user.role != 'Admin':
         # return redirect(url_for('teacher_dashboard'))
        return render_template('login.html', error="Invalid user")
    
    # Fetch all teachers from the database
     cur = mysql.connection.cursor()
     cur.execute("SELECT t.`tbl_id`, (SELECT u.`username` FROM `users` u WHERE u.`user_id` = t.`teacher_id`) , (SELECT c.`title` FROM `courses` c WHERE c.`course_id` = t.`course_id`), t.`created_at` FROM `teachers` t WHERE t.`status` = 1")
     teachers = cur.fetchall()
     cur.close()

     return render_template('admin_manage_teachers.html', teachers= teachers)
    

@app.route('/admin/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO courses (title, description, teacher_id) VALUES (%s, %s, %s)", 
                    (title, description, current_user.id))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('admin_manage_courses'))

    return render_template('add_course.html')

@app.route('/admin/add_teacher', methods=['GET', 'POST'])
@login_required
def add_teacher():
    if request.method == 'POST':
        teacher = request.form['teacher']
        course = request.form['course']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO `teachers`(`teacher_id`, `course_id`) VALUES (%s, %s)", 
                    (teacher, course))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('admin_manage_teachers'))

    # Fetch all teachers and courses for the select boxes
    cur = mysql.connection.cursor()

    # Fetch teachers (teachers are users with the role 'Teacher')
    cur.execute("SELECT user_id, username FROM users WHERE role = 'Teacher'")
    teachers = cur.fetchall()

    # Fetch courses
    cur.execute("SELECT course_id, title FROM courses")
    courses = cur.fetchall()

    cur.close()

    # Pass the data to the template
    return render_template('add_teacher.html', teachers=teachers, courses=courses)

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    cur = mysql.connection.cursor()

    # Fetch the course details
    cur.execute("SELECT course_id, title, description, teacher_id FROM courses WHERE course_id = %s", (course_id,))
    course = cur.fetchone()

    if not course:
        cur.close()
        return redirect(url_for('admin_manage_courses'))  # Course not found

    # Check if the current user is the teacher who created the course or an admin
    if current_user.role != 'Admin' and current_user.id != course[3]:  # course[3] is teacher_id
        cur.close()
        return redirect(url_for('admin_manage_courses'))  # Unauthorized access

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        cur.execute("UPDATE courses SET title = %s, description = %s WHERE course_id = %s", 
                    (title, description, course_id))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('admin_manage_courses'))

    cur.close()
    return render_template('edit_course.html', course=course)


@app.route('/view_course/<int:course_id>')
@login_required
def view_course(course_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT title, description, created_at FROM courses WHERE course_id = %s", (course_id,))
    courses = cur.fetchone()  # Fetch all courses for this teacher
    cur.close()

    if current_user.role != 'Teacher':
        return render_template('view_course.html', courses=courses)
    else:
        return render_template('teacher_view_course.html', courses=courses)

    
@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    if current_user.role != 'Teacher':
        return redirect(url_for('admin_dashboard'))
    
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM courses WHERE course_id = %s AND teacher_id = %s", 
                (course_id, current_user.id))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('teacher_manage_courses'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if current_user.role != 'Admin':
        return redirect(url_for('teacher_dashboard'))
    
    cur = mysql.connection.cursor()

    # Get total users count
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    # Get total courses count
    cur.execute("SELECT COUNT(*) FROM courses")
    total_courses = cur.fetchone()[0]

    # Get total teachers assigned count
    cur.execute("SELECT COUNT(*) FROM teachers WHERE `status` = 1")
    total_teachers = cur.fetchone()[0]

    # Get active sessions (assuming active users have a `last_login` timestamp)
    # cur.execute("SELECT COUNT(*) FROM users WHERE last_login >= NOW() - INTERVAL 30 MINUTE")
    # active_sessions = cur.fetchone()[0]

    # Get recent activities (limit to 5 latest actions)
    # cur.execute("SELECT message FROM activity_log ORDER BY created_at DESC LIMIT 5")
    # recent_activities = [row[0] for row in cur.fetchall()]

    cur.close()

    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           total_courses=total_courses,
                           total_teachers=total_teachers) 
                           # active_sessions=active_sessions,
                           # recent_activities=recent_activities)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# Define the activate_user and deactivate_user Routes
@app.route('/activate_user/<int:user_id>', methods=['POST'])
@login_required
def activate_user(user_id):
    # Activate the user
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET is_active = 1 WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('manage_users'))

@app.route('/deactivate_user/<int:user_id>', methods=['POST'])
@login_required
def deactivate_user(user_id):
    # Deactivate the user
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET is_active = 0 WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()

    return redirect(url_for('manage_users'))

# Teacher Dashboard
@app.route('/teacher_dashboard')
@login_required
def teacher_dashboard():
    # Fetch quick stats for the teacher
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM teachers WHERE teacher_id = %s AND `status` = 1", (current_user.id,))
    total_courses = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM submissions WHERE course_id IN (SELECT course_id FROM courses WHERE teacher_id = %s) AND grade IS NULL", (current_user.id,))
    pending_submissions = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT student_id) FROM enrollments WHERE course_id IN (SELECT course_id FROM courses WHERE teacher_id = %s)", (current_user.id,))
    total_students = cur.fetchone()[0]

    cur.close()

    return render_template('teacher_dashboard.html', total_courses=total_courses, pending_submissions=pending_submissions, total_students=total_students)

# Teacher route to manage their own courses
@app.route('/teacher/manage_courses')
@login_required
def teacher_manage_courses():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))
    
    # Fetch courses taught by the current teacher
    cur = mysql.connection.cursor()
    cur.execute("SELECT t.course_id, (SELECT c.title FROM courses c WHERE c.course_id = t.course_id ), (SELECT  c.description FROM courses c WHERE c.course_id = t.course_id ) FROM teachers t WHERE t.teacher_id = %s AND t.`status` = 1", (current_user.id,))
    courses = cur.fetchall()
    cur.close()

    return render_template('teacher_manage_courses.html', courses=courses)

# Teacher route to manage students
@app.route('/teacher/manage_students')
@login_required
def teacher_manage_students():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))
    
    # Fetch courses assigned to the teacher
    cur = mysql.connection.cursor()
    cur.execute("SELECT t.`course_id`, (SELECT  c.`title` FROM courses c WHERE c.course_id = t.course_id) FROM teachers t WHERE t.teacher_id = %s AND t.`status` = 1", (current_user.id,))
    courses = cur.fetchall()
    cur.close()

    return render_template('teacher_manage_students.html', courses=courses)

# fetch students
@app.route('/teacher/get_students')
@login_required
def get_students():
    course_id = request.args.get('course_id')
    
    # Fetch all students
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, email FROM users WHERE role = 'Student'")
    students = cur.fetchall()

    # Fetch enrolled students for the selected course
    cur.execute("SELECT student_id FROM enrollments WHERE course_id = %s", (course_id,))
    enrolled_students = {row[0] for row in cur.fetchall()}
    cur.close()

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

# Add a route to handle enrollment/unenrollment of students:
@app.route('/teacher/enroll_students', methods=['POST'])
@login_required
def enroll_students():
    course_id = request.form['course_id']
    student_ids = request.form.getlist('student_ids')

    cur = mysql.connection.cursor()

    # Remove all existing enrollments for the course
    cur.execute("DELETE FROM enrollments WHERE course_id = %s", (course_id,))

    # Add new enrollments
    for student_id in student_ids:
        cur.execute("INSERT INTO enrollments (student_id, course_id) VALUES (%s, %s)",
                    (student_id, course_id))

    mysql.connection.commit()
    cur.close()

    flash('Enrollments updated successfully!', 'success')
    return redirect(url_for('teacher_manage_students'))

# Teacher route to update profile
@app.route('/teacher/profile', methods=['GET', 'POST'])
@login_required
def teacher_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        # Update the user's profile in the database
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                    (username, email, current_user.id))
        mysql.connection.commit()
        cur.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('teacher_profile'))

    return render_template('teacher_profile.html')

# change password
@app.route('/teacher/change_password', methods=['POST'])
@login_required
def teacher_change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    # Verify the current password
    cur = mysql.connection.cursor()
    cur.execute("SELECT password_hash FROM users WHERE user_id = %s", (current_user.id,))
    user = cur.fetchone()
    cur.close()

    if user and bcrypt.checkpw(current_password.encode('utf-8'), user[0].encode('utf-8')):
        if new_password == confirm_password:
            # Hash the new password
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Update the password in the database
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s",
                        (new_password_hash, current_user.id))
            mysql.connection.commit()
            cur.close()

            flash('Password changed successfully!', 'success')
        else:
            flash('New passwords do not match.', 'error')
    else:
        flash('Current password is incorrect.', 'error')

    return redirect(url_for('teacher_profile'))

# enable/disable 2fa
@app.route('/enable_2fa')
@login_required
def enable_2fa():
    # Generate a new secret key for 2FA
    secret_key = generate_secret_key()

    # Update the user's secret key in the database
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET secret_key = %s WHERE user_id = %s",
                (secret_key, current_user.id))
    mysql.connection.commit()
    cur.close()

    flash('2FA enabled successfully!', 'success')
    return redirect(url_for('teacher_profile'))

@app.route('/disable_2fa')
@login_required
def disable_2fa():
    # Remove the user's secret key from the database
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET secret_key = NULL WHERE user_id = %s", (current_user.id,))
    mysql.connection.commit()
    cur.close()

    flash('2FA disabled successfully!', 'success')
    return redirect(url_for('teacher_profile'))

# route to fetch submissions for the teacher's courses:
@app.route('/view_submissions')
@login_required
def view_submissions():
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))
    
    # Fetch submissions for the teacher's courses
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT s.submission_id, u.username, c.title, s.submission_date, s.grade, s.feedback
        FROM submissions s
        JOIN users u ON s.student_id = u.user_id        
        JOIN courses c ON s.course_id = c.course_id
        JOIN teachers t ON s.course_id = t.course_id
        WHERE t.teacher_id = %s
    """, (current_user.id,))
    submissions = cur.fetchall()
    cur.close()

    return render_template('view_submissions.html', submissions=submissions)

    # route to handle grading submission

@app.route('/grade_submission/<int:submission_id>', methods=['POST'])
@login_required
def grade_submission(submission_id):
    grade = request.form['grade']

    cur = mysql.connection.cursor()
    cur.execute("UPDATE submissions SET grade = %s WHERE submission_id = %s", (grade, submission_id))
    mysql.connection.commit()
    cur.close()

    flash('Grade updated successfully!', 'success')
    return redirect(url_for('view_submissions'))

# route to handle adding feedback:
@app.route('/add_feedback/<int:submission_id>', methods=['POST'])
@login_required
def add_feedback(submission_id):
    feedback = request.form['feedback']

    cur = mysql.connection.cursor()
    cur.execute("UPDATE submissions SET feedback = %s WHERE submission_id = %s", (feedback, submission_id))
    mysql.connection.commit()
    cur.close()

    flash('Feedback updated successfully!', 'success')
    return redirect(url_for('view_submissions'))

# route to view detailed information about a submission
@app.route('/view_submission_details/<int:submission_id>')
@login_required
def view_submission_details(submission_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT s.submission_id, u.username, c.title, s.submission_date, s.grade, s.feedback, s.file_path
        FROM submissions s
        JOIN users u ON s.student_id = u.user_id
        JOIN courses c ON s.course_id = c.course_id
        WHERE s.submission_id = %s
    """, (submission_id,))
    submission = cur.fetchone()
    cur.close()

    if not submission:
        flash('Submission not found.', 'error')
        return redirect(url_for('view_submissions'))

    return render_template('view_submission_details.html', submission=submission)

# This route allows teachers to upload assignments for their courses.

# Configure upload folder for assignments
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
            # Save the file
            filename = f"{current_user.id}_{course_id}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Insert assignment into the database
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO assignments (course_id, title, description, due_date, file_path)
                VALUES (%s, %s, %s, %s, %s)
            """, (course_id, title, description, due_date, file_path))
            mysql.connection.commit()
            cur.close()

            flash('Assignment uploaded successfully!', 'success')
        else:
            flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')

        return redirect(url_for('upload_assignment'))

    # Fetch courses taught by the current teacher
    cur = mysql.connection.cursor()
    cur.execute("SELECT course_id, title FROM courses WHERE teacher_id = %s", (current_user.id,))
    courses = cur.fetchall()
    cur.close()

    # Fetch assignments for the teacher's courses
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT a.assignment_id, c.title, a.title, a.description, a.due_date, a.file_path
        FROM assignments a
        JOIN courses c ON a.course_id = c.course_id
        WHERE c.teacher_id = %s
    """, (current_user.id,))
    assignments = cur.fetchall()
    cur.close()

    return render_template('teacher_upload_assignment.html', courses=courses, assignments=assignments)


# Add a route to allow teachers to download assignment files.

@app.route('/download_assignment/<path:file_path>')
@login_required
def download_assignment(file_path):
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_path, as_attachment=True)

# Error Handlers in Flask
# All errors are handled here 
# 

# Handle 404 (Page Not Found) errors
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

@app.route('/download_submission/<path:file_path>')
@login_required
def download_submission(file_path):
    if current_user.role != 'Teacher':
        return redirect(url_for('teacher_dashboard'))
    
    # Ensure the file_path is safe and within the allowed directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_path, as_attachment=True)

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
    cur = mysql.connection.cursor()

    # Get total enrolled courses
    cur.execute("SELECT COUNT(*) FROM enrollments WHERE student_id = %s", (current_user.id,))
    total_courses = cur.fetchone()[0]

    # Get pending submissions (assignments not yet submitted)
    cur.execute("SELECT COUNT(*) FROM assignments WHERE course_id IN (SELECT course_id FROM enrollments WHERE student_id = %s) AND assignment_id NOT IN (SELECT assignment_id FROM submissions WHERE student_id = %s)", (current_user.id, current_user.id))
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

# This page lists all the courses the student is enrolled in.
@app.route('/student_courses')
@login_required
def student_courses():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch enrolled courses
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.course_id, c.title, c.description
        FROM courses c
        JOIN enrollments e ON c.course_id = e.course_id
        WHERE e.student_id = %s
    """, (current_user.id,))
    courses = cur.fetchall()
    cur.close()

    return render_template('student_courses.html', courses=courses)

# This page allows students to view their submissions and grades.
@app.route('/student_submissions')
@login_required
def student_submissions():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    # Fetch submissions for the student
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT s.submission_id, c.title, s.submission_date, s.grade, s.feedback
        FROM submissions s
        JOIN courses c ON s.course_id = c.course_id
        WHERE s.student_id = %s
    """, (current_user.id,))
    submissions = cur.fetchall()

    # Fetch enrolled courses
    cur.execute("""
        SELECT c.course_id, c.title
        FROM courses c
        JOIN enrollments e ON c.course_id = e.course_id
        WHERE e.student_id = %s
    """, (current_user.id,))
    enrolled_courses = cur.fetchall()

    # Fetch assignments for the enrolled courses
    cur.execute("""
        SELECT a.assignment_id, a.title
        FROM assignments a
        WHERE a.course_id IN (SELECT course_id FROM enrollments WHERE student_id = %s)
    """, (current_user.id,))
    assignments = cur.fetchall()

    cur.close()

    return render_template('student_submissions.html', submissions=submissions, enrolled_courses=enrolled_courses, assignments=assignments)

# This page allows students to update their profile information.
@app.route('/student_profile', methods=['GET', 'POST'])
@login_required
def student_profile():
    if current_user.role != 'Student':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        # Update the student's profile in the database
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                    (username, email, current_user.id))
        mysql.connection.commit()
        cur.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('student_profile'))

    return render_template('student_profile.html')

# submit assignments

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
        # Save the file
        filename = f"{current_user.id}_{assignment_id}_{file.filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Insert submission into the database
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO submissions (student_id, course_id, assignment_id, file_path)
            VALUES (%s, %s, %s, %s)
        """, (current_user.id, course_id, assignment_id, file_path))
        mysql.connection.commit()
        cur.close()

        flash('Assignment submitted successfully!', 'success')
    else:
        flash('Invalid file type. Allowed types: pdf, doc, docx, txt.', 'error')

    return redirect(url_for('student_submissions'))

if __name__ == '__main__':
    app.run(debug=True)