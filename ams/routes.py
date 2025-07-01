from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from models import db, User, Report
from werkzeug.security import generate_password_hash, check_password_hash
import datetime # Import the datetime module

# Define blueprints for modularity
auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login, role selection, and department selection.
    Includes basic form validation.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')
        remember_me = request.form.get('remember_me')

        # Basic server-side validation
        if not email or not password or not role or not department:
            flash('All fields are required for login.', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # Check if selected role and department match user's stored role/department
            if user.role == role and user.department == department:
                login_user(user, remember=remember_me)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                flash('Role or Department mismatch. Please select your registered role and department.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles new user registration.
    Includes basic form validation.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        institution = request.form.get('institution')
        password = request.form.get('password')
        role = request.form.get('role')
        department = request.form.get('department')
        ministry_rating = request.form.get('ministry_rating')

        # Basic server-side validation for required fields
        if not all([full_name, phone_number, email, institution, password, role, department]):
            flash('All fields are required to sign up.', 'danger')
            return redirect(url_for('auth.signup'))
        
        # Validate email format (simple check)
        if '@' not in email or '.' not in email:
            flash('Invalid email format.', 'danger')
            return redirect(url_for('auth.signup'))

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered. Please login or use a different email.', 'danger')
            return redirect(url_for('auth.signup'))

        new_user = User(
            full_name=full_name,
            phone_number=phone_number,
            email=email,
            institution=institution,
            role=role,
            department=department,
            ministry_rating=int(ministry_rating) if ministry_rating else 0
        )
        new_user.set_password(password) # Hash the password

        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')

@main_bp.route('/logout')
@login_required
def logout():
    """
    Logs out the current user.
    """
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Displays the role-based dashboard with filtering and search capabilities for admins.
    """
    user_role = current_user.role
    user_department = current_user.department
    search_query = request.args.get('search_query', '').strip()

    if user_role == 'Attachee':
        # Attachee dashboard: show forms for submitting reports and their own reports
        attachee_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).all()
        return render_template('dashboard.html', user_role=user_role, attachee_reports=attachee_reports)
    
    elif user_role in ['Supervisor', 'Director']:
        # Admins dashboard: view all users, reports, ratings, comments
        # Filtering and search for users
        users_query = User.query
        if user_role == 'Supervisor':
            # Supervisors only see users from their department
            users_query = users_query.filter_by(department=user_department)
        
        if search_query:
            # Simple search across full_name, email, institution, role, department
            search_pattern = f"%{search_query}%"
            users_query = users_query.filter(
                (User.full_name.ilike(search_pattern)) |
                (User.email.ilike(search_pattern)) |
                (User.institution.ilike(search_pattern)) |
                (User.role.ilike(search_pattern)) |
                (User.department.ilike(search_pattern))
            )
        all_users = users_query.all()

        # Filtering and search for reports
        reports_query = Report.query.join(User) # Join with User to filter by department
        if user_role == 'Supervisor':
            # Supervisors only see reports from their department's attachees
            reports_query = reports_query.filter(User.department == user_department)
        
        if search_query:
            # Simple search across report details, subject, and attachee name
            search_pattern = f"%{search_query}%"
            reports_query = reports_query.filter(
                (Report.details.ilike(search_pattern)) |
                (Report.subject.ilike(search_pattern)) |
                (Report.reason.ilike(search_pattern)) |
                (User.full_name.ilike(search_pattern))
            )
        all_reports = reports_query.order_by(Report.date_submitted.desc()).all()

        return render_template('dashboard.html', user_role=user_role,
                               all_users=all_users, all_reports=all_reports,
                               user_department=user_department, search_query=search_query)
    else:
        flash('Unknown role. Please contact administrator.', 'danger')
        logout_user()
        return redirect(url_for('auth.login'))

@main_bp.route('/submit_report', methods=['GET', 'POST'])
@login_required
def submit_report():
    """
    Allows attachees to submit reports.
    Includes robust validation for report-specific fields.
    """
    if current_user.role != 'Attachee':
        flash('Only Attachees can submit reports.', 'danger')
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        details = request.form.get('details')
        subject = request.form.get('subject') # For complaints/recommendations
        
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        reason = request.form.get('reason')

        # Basic validation for common fields
        if not report_type or not details:
            flash('Report type and details are required.', 'danger')
            return redirect(url_for('main.submit_report'))

        new_report = Report(
            user_id=current_user.id,
            report_type=report_type,
            details=details
        )

        if report_type == 'absent_days':
            if not start_date_str or not end_date_str or not reason:
                flash('Start date, end date, and reason are required for absent days.', 'danger')
                return redirect(url_for('main.submit_report'))
            try:
                new_report.start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d').date()
                new_report.end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d').date()
                new_report.reason = reason
                if new_report.start_date > new_report.end_date:
                    flash('Start date cannot be after end date.', 'danger')
                    return redirect(url_for('main.submit_report'))
            except ValueError:
                flash('Invalid date format for absent days. Please use YYYY-MM-DD.', 'danger')
                return redirect(url_for('main.submit_report'))
        elif report_type in ['complaint', 'recommendation']:
            if not subject:
                flash('Subject is required for complaints and recommendations.', 'danger')
                return redirect(url_for('main.submit_report'))
            new_report.subject = subject

        db.session.add(new_report)
        db.session.commit()
        flash('Report submitted successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('submit_report.html')

@main_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """
    Allows Supervisors/Directors to edit user details.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to edit user accounts.', 'danger')
        return redirect(url_for('main.dashboard'))

    user_to_edit = User.query.get_or_404(user_id)

    # Supervisors can only edit users in their department, Directors can edit anyone
    if current_user.role == 'Supervisor' and user_to_edit.department != current_user.department:
        flash('You can only edit users within your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        user_to_edit.full_name = request.form.get('full_name')
        user_to_edit.phone_number = request.form.get('phone_number')
        user_to_edit.email = request.form.get('email')
        user_to_edit.institution = request.form.get('institution')
        user_to_edit.role = request.form.get('role')
        user_to_edit.department = request.form.get('department')
        user_to_edit.ministry_rating = int(request.form.get('ministry_rating', 0))

        # Basic validation
        if not all([user_to_edit.full_name, user_to_edit.phone_number, user_to_edit.email,
                    user_to_edit.institution, user_to_edit.role, user_to_edit.department]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('main.edit_user', user_id=user_id))

        # Check for duplicate email if changed
        if user_to_edit.email != User.query.get(user_id).email:
            existing_email_user = User.query.filter_by(email=user_to_edit.email).first()
            if existing_email_user and existing_email_user.id != user_id:
                flash('Email address already exists for another user.', 'danger')
                return redirect(url_for('main.edit_user', user_id=user_id))

        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('edit_user.html', user=user_to_edit)

@main_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """
    Allows Supervisors/Directors to delete user accounts.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to delete user accounts.', 'danger')
        return redirect(url_for('main.dashboard'))

    user_to_delete = User.query.get_or_404(user_id)

    # Prevent deleting self
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Supervisors can only delete users in their department, Directors can delete anyone
    if current_user.role == 'Supervisor' and user_to_delete.department != current_user.department:
        flash('You can only delete users within your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Delete associated reports first to avoid foreign key constraints
    Report.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User and their associated reports deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    """
    Allows Supervisors/Directors to delete reports.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to delete reports.', 'danger')
        return redirect(url_for('main.dashboard'))

    report_to_delete = Report.query.get_or_404(report_id)

    # Supervisors can only delete reports from their department's attachees
    if current_user.role == 'Supervisor' and report_to_delete.author.department != current_user.department:
        flash('You can only delete reports from your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    db.session.delete(report_to_delete)
    db.session.commit()
    flash('Report deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))

@main_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """
    Displays and allows editing of the current user's account details.
    """
    user = current_user
    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.phone_number = request.form.get('phone_number')
        user.email = request.form.get('email')
        user.institution = request.form.get('institution')
        # Role and Department are not editable by the user themselves
        user.ministry_rating = int(request.form.get('ministry_rating', 0))

        # Basic validation
        if not all([user.full_name, user.phone_number, user.email, user.institution]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('main.account'))

        # Check for duplicate email if changed
        if user.email != User.query.get(current_user.id).email:
            existing_email_user = User.query.filter_by(email=user.email).first()
            if existing_email_user and existing_email_user.id != current_user.id:
                flash('Email address already exists for another user.', 'danger')
                return redirect(url_for('main.account'))

        db.session.commit()
        flash('Account details updated successfully!', 'success')
        return redirect(url_for('main.account'))

    return render_template('account.html', user=user)

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Placeholder for initiating password reset.
    In a real application, this would send an email with a reset link.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        # Here, you would typically generate a token, save it to the database
        # with an expiry, and send an email to the user with a reset link.
        flash(f'If {email} is registered, a password reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html')

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Placeholder for resetting password using a token.
    In a real application, this would validate the token and allow password change.
    """
    # Here, you would validate the token from the URL,
    # find the user associated with it, and check expiry.
    # For now, we'll just show a form.
    
    # Example: if token is invalid or expired
    # flash('Invalid or expired password reset token.', 'danger')
    # return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both password fields are required.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        # In a real app:
        # user = User.query.filter_by(reset_token=token).first()
        # user.set_password(new_password)
        # user.reset_token = None # Clear the token
        # db.session.commit()

        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)


@main_bp.route('/settings')
@login_required
def settings():
    """
    Displays the settings page.
    """
    return render_template('settings.html')

@main_bp.route('/about')
def about():
    """
    Displays the about page (accessible without login).
    """
    return render_template('about.html')
