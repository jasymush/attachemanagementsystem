from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature, BadSignature
import datetime
import time

# NEW: Import for explicit join conditions
from sqlalchemy import or_

# Import models and forms from your project
from models import db, User, Report
from forms import LoginForm, RegistrationForm, ReportForm, EditUserForm, AccountEditForm, ForgotPasswordForm, ResetPasswordForm, ReportReviewForm

# Define blueprints for modularity
auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login, role selection, and department selection.
    Includes basic form validation and account activation check.
    """
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        role = form.role.data
        department = form.department.data
        remember_me = form.remember_me.data

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account is awaiting administrator approval. Please contact your department head for activation.', 'warning')
                return redirect(url_for('auth.login'))

            if user.role == role and user.department == department:
                login_user(user, remember=remember_me)
                flash(f'Logged in successfully as {user.full_name}!', 'success')
                return redirect(url_for('main.dashboard'))
            else:
                flash('Role or Department mismatch. Please select your registered role and department.', 'danger')
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('login.html', form=form)

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles new user registration.
    Includes basic form validation. New accounts are created as inactive.
    """
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        full_name = form.full_name.data
        phone_number = form.phone_number.data
        email = form.email.data
        institution = form.institution.data
        password = form.password.data
        role = form.role.data
        department = form.department.data
        ministry_rating = form.ministry_rating.data

        new_user = User(
            full_name=full_name,
            phone_number=phone_number,
            email=email,
            institution=institution,
            role=role,
            department=department,
            ministry_rating=int(ministry_rating) if ministry_rating else 0,
            is_active=False
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash(f'Account for {full_name} created successfully! It is now awaiting administrator approval.', 'success')
        return redirect(url_for('auth.login'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('signup.html', form=form)

@main_bp.route('/logout')
@login_required
def logout():
    """
    Logs out the current user.
    """
    flash(f'You have been logged out, {current_user.full_name}.', 'info')
    logout_user()
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Displays the role-based dashboard with filtering, search, and pagination capabilities for admins.
    """
    user_role = current_user.role
    user_department = current_user.department
    search_query = request.args.get('search_query', '').strip()
    users_page = request.args.get('users_page', 1, type=int)
    reports_page = request.args.get('reports_page', 1, type=int)
    per_page = 10

    if user_role == 'Attachee':
        # Fetch reports for the current attachee
        attachee_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_submitted.desc()).all()
        report_form = ReportForm() # Form for submitting new reports
        return render_template('dashboard.html', user_role=user_role, attachee_reports=attachee_reports, form=report_form)
    
    elif user_role in ['Supervisor', 'Director']:
        users_query = User.query
        
        # Supervisors/Directors can only see users in their department, unless they are ICT admin
        if not (user_role in ['Supervisor', 'Director'] and user_department == 'ICT'):
            users_query = users_query.filter_by(department=user_department)

        if search_query:
            search_pattern = f"%{search_query}%"
            users_query = users_query.filter(
                (User.full_name.ilike(search_pattern)) |
                (User.email.ilike(search_pattern)) |
                (User.institution.ilike(search_pattern)) |
                (User.role.ilike(search_pattern)) |
                (User.department.ilike(search_pattern))
            )
        
        paginated_users = users_query.paginate(page=users_page, per_page=per_page, error_out=False)
        all_users = paginated_users.items

        # MODIFIED: Explicitly define joins to avoid AmbiguousForeignKeysError
        # Join Report with User (as author) for filtering
        reports_query = Report.query.join(Report.author)
        
        # Supervisors/Directors can only see reports from their department
        if user_role in ['Supervisor', 'Director']:
            reports_query = reports_query.filter(Report.author.has(department=user_department))
        
        if search_query:
            search_pattern = f"%{search_query}%"
            # Use OR to search across different fields, including joined relationships
            reports_query = reports_query.filter(
                (Report.details.ilike(search_pattern)) |
                (Report.subject.ilike(search_pattern)) |
                (Report.reason.ilike(search_pattern)) |
                (Report.author.has(User.full_name.ilike(search_pattern))) | # Search by author's name
                (Report.reviewer.has(User.full_name.ilike(search_pattern))) # Search by reviewer's name
            )
        
        # Efficiently load both author and reviewer without separate joins that cause ambiguity
        # The joins are already handled by the filters and relationship loading below
        reports_query = reports_query.options(db.joinedload(Report.author), db.joinedload(Report.reviewer))

        paginated_reports = reports_query.order_by(Report.date_submitted.desc()).paginate(page=reports_page, per_page=per_page, error_out=False)
        all_reports = paginated_reports.items
        
        # Pass an empty ReportReviewForm instance for the template
        review_form = ReportReviewForm()

        return render_template('dashboard.html', user_role=user_role,
                               paginated_users=paginated_users, all_users=all_users,
                               paginated_reports=paginated_reports, all_reports=all_reports,
                               user_department=user_department, search_query=search_query,
                               review_form=review_form) # Pass review_form to template
    else:
        flash('Unknown role. Please contact administrator.', 'danger')
        logout_user()
        return redirect(url_for('auth.login'))

@main_bp.route('/activate_user/<int:user_id>', methods=['POST'])
@login_required
def activate_user(user_id):
    """
    Allows Supervisors/Directors to activate a new user account.
    ICT Directors/Supervisors can activate any user.
    Other Supervisors/Directors can activate users only within their department.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to activate user accounts.', 'danger')
        return redirect(url_for('main.dashboard'))

    user_to_activate = db.session.get(User, user_id)
    if not user_to_activate:
        flash('User not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    if user_to_activate.id == current_user.id:
        flash('You cannot activate your own account.', 'warning')
        return redirect(url_for('main.dashboard'))

    is_ict_admin = (current_user.role in ['Supervisor', 'Director'] and current_user.department == 'ICT')
    is_same_department_admin = (current_user.role in ['Supervisor', 'Director'] and user_to_activate.department == current_user.department)

    if not is_ict_admin and not is_same_department_admin:
        flash('You do not have permission to activate users outside your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    if user_to_activate.is_active:
        flash(f'User {user_to_activate.full_name} is already active.', 'info')
    else:
        user_to_activate.is_active = True
        db.session.commit()
        flash(f'User {user_to_activate.full_name} has been activated successfully!', 'success')
    
    return redirect(url_for('main.dashboard', users_page=request.args.get('users_page', 1, type=int), reports_page=request.args.get('reports_page', 1, type=int), search_query=request.args.get('search_query', '')))


@main_bp.route('/submit_report', methods=['GET', 'POST'])
@login_required
def submit_report():
    """
    Allows attachees to submit reports.
    Includes robust validation for report-specific fields using Flask-WTF.
    Sends an email notification to the supervisor.
    """
    if current_user.role != 'Attachee':
        flash('You do not have permission to submit reports.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = ReportForm()
    if form.validate_on_submit():
        new_report = Report(
            user_id=current_user.id,
            report_type=form.report_type.data,
            details=form.details.data,
            subject=form.subject.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            reason=form.reason.data,
            status='Pending' # Set initial status to Pending
        )
        db.session.add(new_report)
        db.session.commit()
        flash(f'Report "{new_report.subject or new_report.report_type.replace("_", " ").title()}" submitted successfully by {current_user.full_name}! It is now pending review.', 'success')

        department_supervisors = User.query.filter(
            User.department == current_user.department,
            User.role == 'Supervisor'
        ).all()

        if department_supervisors:
            recipients = [admin.email for admin in department_supervisors if admin.email]
            if recipients:
                try:
                    msg = Message("New Attachee Report Submitted",
                                  recipients=recipients,
                                  sender=current_app.config['MAIL_DEFAULT_SENDER'])
                    msg.body = f"""
Dear Supervisor,

A new report has been submitted by {current_user.full_name} ({current_user.department}).

Report Type: {new_report.report_type.replace('_', ' ').title()}
Details: {new_report.details}
Date Submitted: {new_report.date_submitted.strftime('%Y-%m-%d %H:%M')}
Current Status: {new_report.status}

Please log in to the Attaches Management System to review it: {url_for('auth.login', _external=True)}

Regards,
Attaches Management System
"""
                    current_app.extensions['mail'].send(msg)
                    flash(f'Notification email sent to department supervisors regarding "{new_report.subject or new_report.report_type.replace("_", " ").title()}".', 'info')
                except Exception as e:
                    flash(f'Failed to send notification email to department supervisors: {e}', 'warning')
            else:
                flash('No valid email addresses found for department supervisors to send notification.', 'warning')
        else:
            flash('No department supervisors found to send notification.', 'warning')

        return redirect(url_for('main.dashboard'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')
    
    return render_template('submit_report.html', form=form)

@main_bp.route('/report/<int:report_id>/review', methods=['GET', 'POST'])
@login_required
def review_report(report_id):
    """
    Allows Supervisors/Directors to review a submitted report (approve/deny) and provide feedback.
    """
    report_to_review = db.session.get(Report, report_id)
    if not report_to_review:
        flash('Report not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Permission check: Only supervisors/directors from the same department OR ICT admin
    is_ict_admin = (current_user.role in ['Supervisor', 'Director'] and current_user.department == 'ICT')
    is_same_department_reviewer = (current_user.role in ['Supervisor', 'Director'] and report_to_review.author.department == current_user.department)

    if not (is_ict_admin or is_same_department_reviewer):
        flash('You do not have permission to review this report.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Prevent reviewing already reviewed reports by non-ICT supervisors if not from their department.
    # ICT admins can always view/re-review.
    if report_to_review.status != 'Pending' and not is_ict_admin:
        flash('This report has already been reviewed and cannot be changed by you.', 'warning')
        return redirect(url_for('main.dashboard'))

    form = ReportReviewForm(obj=report_to_review)
    form.report_id.data = report_to_review.id # Ensure hidden field is populated

    if form.validate_on_submit():
        report_to_review.status = form.status.data
        report_to_review.supervisor_feedback = form.supervisor_feedback.data
        report_to_review.reviewed_by_id = current_user.id
        report_to_review.reviewed_at = datetime.datetime.utcnow()
        db.session.commit()
        
        flash(f'Report by {report_to_review.author.full_name} has been {report_to_review.status.lower()}!', 'success')

        # Send email notification to the attachee
        try:
            msg = Message(f"Your Report '{report_to_review.subject or report_to_review.report_type.replace('_', ' ').title()}' Has Been Reviewed",
                          recipients=[report_to_review.author.email],
                          sender=current_app.config['MAIL_DEFAULT_SENDER'])
            msg.body = f"""
Dear {report_to_review.author.full_name},

Your report '{report_to_review.subject or report_to_review.report_type.replace('_', ' ').title()}' has been reviewed.

Status: {report_to_review.status}
Reviewed by: {current_user.full_name} ({current_user.role}, {current_user.department})
Reviewed at: {report_to_review.reviewed_at.strftime('%Y-%m-%d %H:%M')}

Feedback:
{report_to_review.supervisor_feedback if report_to_review.supervisor_feedback else 'No specific feedback provided.'}

Please log in to the Attaches Management System to view your dashboard: {url_for('auth.login', _external=True)}

Regards,
Attaches Management System
"""
            current_app.extensions['mail'].send(msg)
            flash(f'Notification email sent to {report_to_review.author.full_name} regarding their report review.', 'info')
        except Exception as e:
            flash(f'Failed to send notification email to attachee: {e}', 'warning')

        return redirect(url_for('main.dashboard'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('review_report.html', report=report_to_review, form=form)


@main_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    """
    Allows Supervisors/Directors to edit user details.
    Uses Flask-WTF for form handling and validation.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to edit user accounts.', 'danger')
        return redirect(url_for('main.dashboard'))

    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit:
        flash('User not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    if current_user.role == 'Supervisor' and user_to_edit.department != current_user.department:
        flash('You can only edit users within your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = EditUserForm(obj=user_to_edit, user_id=user_to_edit.id)
    form.original_email.data = user_to_edit.email

    if form.validate_on_submit():
        form.populate_obj(user_to_edit)
        db.session.commit()
        flash(f'User account for {user_to_edit.full_name} updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('edit_user.html', form=form, user=user_to_edit)

@main_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """
    Allows Supervisors/Directors to delete user accounts.
    """
    if current_user.role not in ['Supervisor', 'Director']:
        flash('You do not have permission to delete user accounts.', 'danger')
        return redirect(url_for('main.dashboard'))

    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('User not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('main.dashboard'))

    if current_user.role == 'Supervisor' and user_to_delete.department != current_user.department:
        flash('You can only delete users within your department.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Delete associated reports first due to foreign key constraints
    Report.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'User {user_to_delete.full_name} and their associated reports deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/report/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    """
    Allows attachees to delete their own pending reports,
    and Supervisors/Directors to delete any report in their department.
    """
    report_to_delete = db.session.get(Report, report_id)
    if not report_to_delete:
        flash('Report not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Check permissions
    is_attachee_owner = (current_user.role == 'Attachee' and report_to_delete.user_id == current_user.id)
    is_supervisor_or_director_in_department = (current_user.role in ['Supervisor', 'Director'] and report_to_delete.author.department == current_user.department)
    is_ict_admin = (current_user.role in ['Supervisor', 'Director'] and current_user.department == 'ICT')

    if not (is_attachee_owner or is_supervisor_or_director_in_department or is_ict_admin):
        flash('You do not have permission to delete this report.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Specific rule: Attachees can only delete PENDING reports
    if is_attachee_owner and report_to_delete.status != 'Pending':
        flash('You can only delete reports that are still pending review.', 'danger')
        return redirect(url_for('main.dashboard'))


    db.session.delete(report_to_delete)
    db.session.commit()
    flash(f'Report "{report_to_delete.subject or report_to_delete.report_type.replace("_", " ").title()}" deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """
    Displays and allows editing of the current user's account details.
    Uses Flask-WTF for form handling and validation.
    """
    user = current_user
    form = AccountEditForm(obj=user)
    form.original_email.data = user.email

    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash(f'Your account details have been updated successfully, {user.full_name}!', 'success')
        return redirect(url_for('main.account'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('account.html', form=form, user=user)

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles initiating password reset by sending a tokenized email.
    """
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            token = s.dumps({'user_id': user.id}, salt='password-reset-salt')
            
            user.reset_token = token
            user.reset_token_timestamp = datetime.datetime.utcnow()
            db.session.commit()

            try:
                msg = Message("Password Reset Request for Attaches Management System",
                              recipients=[email],
                              sender=current_app.config['MAIL_DEFAULT_SENDER'])
                msg.html = f"""
<p>Dear {user.full_name},</p>
<p>You have requested a password reset for your Attaches Management System account.</p>
<p><a href="{url_for('auth.reset_password', token=token, _external=True)}">Reset Password Link</a></p>
<p>This link is valid for 1 hour.</p>
<p>If you did not make this request then please ignore this email and your password will remain unchanged.</p>
<p>Regards,<br>Attaches Management System Team</p>
"""
                current_app.extensions['mail'].send(msg)
                flash(f'A password reset link has been sent to {email}. Please check your inbox.', 'info')
            except Exception as e:
                flash(f'Failed to send password reset email to {email}: {e}', 'warning')
        else:
            flash('If that email is registered with us, a password reset link has been sent to it. Please check your inbox.', 'info')
        
        return redirect(url_for('auth.login'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')
    return render_template('forgot_password.html', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Handles resetting password using a token from the email.
    """
    user = None
    try:
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        user_id = s.loads(token, salt='password-reset-salt')['user_id']
        user = db.session.get(User, user_id)
    except (SignatureExpired, BadTimeSignature, BadSignature):
        flash('The password reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    
    if not user:
        flash('Invalid user for password reset. Please request a new link.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    token_age_limit_seconds = 3600 # 1 hour
    if user.reset_token_timestamp is None or \
       (datetime.datetime.utcnow() - user.reset_token_timestamp).total_seconds() > token_age_limit_seconds:
        flash('The password reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if user.reset_token != token:
        flash('This password reset link has already been used or is invalid. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.new_password.data
        
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_timestamp = None
        db.session.commit()
        flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('auth.login'))
    elif request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Validation Error in {field.replace('_', ' ').title()}: {error}", 'danger')

    return render_template('reset_password.html', form=form, token=token)


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
