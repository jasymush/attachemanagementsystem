from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, IntegerField, TextAreaField, DateField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, NumberRange, ValidationError
from models import User # Import User model for custom validation

class LoginForm(FlaskForm):
    """Form for user login."""
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Select Role', choices=[
        ('', 'Choose your role...'),
        ('Attachee', 'Attachee'),
        ('Supervisor', 'Supervisor'),
        ('Director', 'Director')
    ], validators=[DataRequired()])
    department = SelectField('Select Department', choices=[
        ('', 'Choose your department...'),
        ('ICT', 'ICT'),
        ('Finance', 'Finance'),
        ('Planning', 'Planning'),
        ('Human Resource', 'Human Resource')
    ], validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class RegistrationForm(FlaskForm):
    """Form for new user registration."""
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    institution = StringField('Institution', validators=[DataRequired(), Length(max=100)])
    # Removed Length validator here, relying on JS feedback and DB column length
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    role = SelectField('Select Role', choices=[
        ('', 'Choose your role...'),
        ('Attachee', 'Attachee'),
        ('Supervisor', 'Supervisor'),
        ('Director', 'Director')
    ], validators=[DataRequired()])
    department = SelectField('Select Department', choices=[
        ('', 'Choose your department...'),
        ('ICT', 'ICT'),
        ('Finance', 'Finance'),
        ('Planning', 'Planning'),
        ('Human Resource', 'Human Resource')
    ], validators=[DataRequired()])
    ministry_rating = IntegerField('Ministry Rating (1-5 stars)', validators=[Optional(), NumberRange(min=1, max=5, message='Rating must be between 1 and 5.')], default=0)

    def validate_email(self, email):
        """Custom validator to check if email already exists."""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one.')

    def validate(self, extra_validators=None):
        """
        Custom validation for registration, including ensuring only one Director per department.
        """
        initial_validation = super().validate(extra_validators=extra_validators)
        if not initial_validation:
            return False

        if self.role.data == 'Director':
            # Check if a Director already exists for this department
            existing_director = User.query.filter_by(
                role='Director',
                department=self.department.data
            ).first()
            if existing_director:
                self.department.errors.append(f'A Director already exists for the {self.department.data} department. Only one Director is allowed per department.')
                return False # Validation fails

        return True # All validations passed

class ReportForm(FlaskForm):
    """Form for attachee report submissions."""
    report_type = SelectField('Report Type', choices=[
        ('', 'Select report type...'),
        ('absent_days', 'Days Absent'),
        ('complaint', 'Complaint'),
        ('recommendation', 'Recommendation')
    ], validators=[DataRequired()])
    subject = StringField('Subject', validators=[Optional(), Length(max=200)]) # Optional for absent_days
    details = TextAreaField('Details', validators=[DataRequired()])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    reason = TextAreaField('Reason for Absence', validators=[Optional()])

    def validate(self, extra_validators=None):
        """Custom validation for report types."""
        # Call the parent class's validate method first
        initial_validation = super().validate(extra_validators=extra_validators)
        
        # Perform custom validation only if initial validation passes
        if not initial_validation:
            return False # If basic validators failed, no need for custom logic

        # Custom logic for conditional required fields
        if self.report_type.data == 'absent_days':
            if not self.start_date.data:
                self.start_date.errors.append('Start date is required for absent days.')
            if not self.end_date.data:
                self.end_date.errors.append('End date is required for absent days.')
            if not self.reason.data:
                self.reason.errors.append('Reason for absence is required for absent days.')
            if self.start_date.data and self.end_date.data and self.start_date.data > self.end_date.data:
                self.start_date.errors.append('Start date cannot be after end date.')
        elif self.report_type.data in ['complaint', 'recommendation']:
            if not self.subject.data:
                self.subject.errors.append('Subject is required for complaints and recommendations.')
        
        # Return True if no new errors were added by custom validation, False otherwise
        return not (self.start_date.errors or self.end_date.errors or self.reason.errors or self.subject.errors)


class EditUserForm(FlaskForm):
    """Form for Supervisors/Directors to edit user details."""
    user_id = HiddenField() 

    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    institution = StringField('Institution', validators=[DataRequired(), Length(max=100)])
    role = SelectField('Role', choices=[
        ('Attachee', 'Attachee'),
        ('Supervisor', 'Supervisor'),
        ('Director', 'Director')
    ], validators=[DataRequired()])
    department = SelectField('Department', choices=[
        ('ICT', 'ICT'),
        ('Finance', 'Finance'),
        ('Planning', 'Planning'),
        ('Human Resource', 'Human Resource')
    ], validators=[DataRequired()])
    ministry_rating = IntegerField('Ministry Rating (1-5 stars)', validators=[Optional(), NumberRange(min=1, max=5, message='Rating must be between 1 and 5.')], default=0)
    
    # Store original email to check for duplicates correctly
    original_email = StringField(validators=[Optional()])

    def validate_email(self, email):
        """Custom validator to check for duplicate email, excluding the current user being edited."""
        if email.data != self.original_email.data: # Only check if email has changed
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already registered for another user.')

    def validate(self, extra_validators=None):
        """
        Custom validation for editing users, including ensuring only one Director per department.
        """
        initial_validation = super().validate(extra_validators=extra_validators)
        if not initial_validation:
            return False

        if self.role.data == 'Director':
            # Find if another Director exists in this department, excluding the current user being edited
            existing_director = User.query.filter(
                User.role == 'Director',
                User.department == self.department.data,
                User.id != self.user_id.data # Exclude the current user being edited
            ).first()
            
            if existing_director:
                self.department.errors.append(f'A Director already exists for the {self.department.data} department. Only one Director is allowed per department.')
                return False # Validation fails

        return True # All validations passed

class AccountEditForm(FlaskForm):
    """Form for users to edit their own account details."""
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    institution = StringField('Institution', validators=[DataRequired(), Length(max=100)])
    ministry_rating = IntegerField('Ministry Rating (1-5 stars)', validators=[Optional(), NumberRange(min=1, max=5, message='Rating must be between 1 and 5.')], default=0)

    # Store original email to check for duplicates correctly
    original_email = StringField(validators=[Optional()])

    def validate_email(self, email):
        """Custom validator to check for duplicate email, excluding the current user."""
        if email.data != self.original_email.data: # Only check if email has changed
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already registered for another account.')

    def validate(self, extra_validators=None):
        """
        Custom validation for account editing, including ensuring only one Director per department
        if the user is changing their role to Director.
        """
        initial_validation = super().validate(extra_validators=extra_validators)
        if not initial_validation:
            return False
        return True


class ForgotPasswordForm(FlaskForm):
    """Form for initiating password reset."""
    email = StringField('Email Address', validators=[DataRequired(), Email()])

class ResetPasswordForm(FlaskForm):
    """Form for resetting password with a token."""
    # Removed Length validator here, relying on JS feedback and DB column length
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
