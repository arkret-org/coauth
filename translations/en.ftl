# coauth translation file
# Auto-converted from JSON format

## action

action-back = Back
action-cancel = Cancel
action-continue = Continue
action-create-account = Create Account
action-sign-in = Sign in
action-sign-out = Sign out
action-skip = Skip
action-start-over = Start over

## app

# Human readable name of the application
app-human-name = coauth
# Name of the application
app-name = coauth
# Introduction text displayed on the home page
app-technical-description =
    OpenID Connect discovery document: <a class="cpd-link" data-kind="primary" href="{ $discovery_url }">{ $discovery_url }</a>

## branding

branding-privacy-policy-alt = Link to the service privacy policy
branding-privacy-policy-link = Privacy Policy
branding-terms-and-conditions-alt = Link to the service terms and conditions
branding-terms-and-conditions-link = Terms & Conditions

## common

common-display-name = Display Name
common-email-address = Email address
common-loading = Loading…
common-account-id = Account ID
common-password = Password
common-password-confirm = Confirm password
common-handle = Username

## error

# Error message displayed when an unexpected error occurs
error-unexpected = Unexpected error

## coauth

coauth-account-deactivated-description =
    This account (<em>{ $account_id }</em>) has been deleted. If this is not expected, contact your server administrator.
coauth-account-deactivated-heading = Account deleted
coauth-account-locked-description =
    This account (<em>{ $account_id }</em>) has been locked. If this is not expected, contact your server administrator.
coauth-account-locked-heading = Account locked
coauth-account-logged-out-description = This session has been terminated. Sign out to be able to log back in
coauth-account-logged-out-heading = Session terminated
coauth-back-to-homepage = Go back to the homepage
coauth-captcha-noscript =
    This form is protected by a CAPTCHA and requires JavaScript to be enabled to submit it. Please enable JavaScript in your browser and reload this page.
# Button to change the user's password
coauth-change-password-change = Change password
# Confirmation field for the new password
coauth-change-password-confirm = Confirm password
# Field for the user's current password
coauth-change-password-current = Current password
# Heading on the change password page
coauth-change-password-heading = Change my password
# Field for the user's new password
coauth-change-password-new = New password
# During the registration strand, the user is asked to choose a display name. This is the description of that form.
coauth-choose-display-name-description = This is the name other people will see. You can change this at any time.
# During the registration strand, the user is asked to choose a display name. This is the headline of that form.
coauth-choose-display-name-headline = Choose your display name
coauth-approval-continue-to = Continue to <span>{ $client_name }</span>?
coauth-approval-scope-list-preface = By continuing, you allow <span>{ $client_name }</span> to:
coauth-approval-this-will-setup =
    This will set up { $client_name } (<span>{ $client_uri }</span>) with your <span>{ $server_name }</span> account.
coauth-approval-use-another-account = Use another account
coauth-device-card-access-requested = Access requested
coauth-device-card-device-code = Code
coauth-device-card-generic-device = Device
coauth-device-card-ip-address = IP address
coauth-device-code-link-description = Link a device
coauth-device-code-link-headline = Enter the code displayed on your device
coauth-device-approval-denied-description = You denied access to { $client_name }. You can close this window.
coauth-device-approval-denied-heading = Access denied
coauth-device-approval-granted-description = You granted access to { $client_name }. You can close this window.
coauth-device-approval-granted-heading = Access granted
coauth-device-approval-this-will-setup =
    Another device wants to set up { $client_name } (<span>{ $client_uri }</span>) with your <span>{ $server_name }</span> account. Make sure you recognise that device.
# The automatic device name generated for a client, e.g. 'Element on iPhone'
coauth-device-display-name-client-on-device = { $client_name } on { $device_name }
# Part of the automatic device name for the platfom, e.g. 'Safari for macOS'
coauth-device-display-name-name-for-platform = { $name } for { $platform }
coauth-device-display-name-unknown-device = Unknown device
coauth-email-in-use-description =
    If you have forgotten your account credentials, you can recover your account. You can also start over and use a different email address.
coauth-email-in-use-title = The email address <span>{ $email }</span> is already in use
# Greeting at the top of emails sent to the user
coauth-emails-greeting = Hello { $handle },
coauth-emails-recovery-click-button = Click on the button below to create a new password:
coauth-emails-recovery-copy-link = Copy the following link and paste it into a browser to create a new password:
coauth-emails-recovery-create-new-password = Create new password
coauth-emails-recovery-fallback = The button doesn't work for you?
coauth-emails-recovery-headline = You requested a password reset for your { $server_name } coauth account.
coauth-emails-recovery-subject = Reset your coauth account password ({ $account_id })
coauth-emails-recovery-you-can-ignore =
    If you didn't ask for a new password, you can ignore this email. Your current password will continue to work.
# The body of the email sent to verify an email address (HTML)
coauth-emails-verify-body-html = Your verification code to confirm this email address is: <strong>{ $code }</strong>
# The body of the email sent to verify an email address (text)
coauth-emails-verify-body-text = Your verification code to confirm this email address is: { $code }
# The subject line of the email sent to verify an email address
coauth-emails-verify-subject = Your email verification code is: { $code }
coauth-errors-captcha = CAPTCHA verification failed, please try again
coauth-errors-denied-policy = Denied by policy: { $policy }
coauth-errors-email-banned = Email is banned by the server policy
coauth-errors-email-domain-banned = Email domain is banned by the server policy
coauth-errors-email-domain-not-allowed = Email domain is not allowed by the server policy
coauth-errors-email-not-allowed = Email is not allowed by the server policy
coauth-errors-field-required = This field is required
coauth-errors-invalid-credentials = Invalid credentials
coauth-errors-password-mismatch = Password fields don't match
coauth-errors-rate-limit-exceeded = You've made too many requests in a short period. Please wait a few minutes and try again.
coauth-errors-handle-all-numeric = Username cannot consist solely of numbers
# Error message shown on registration, when the username matches a pattern that is banned by the server policy.
coauth-errors-handle-banned = Username is banned by the server policy
coauth-errors-handle-invalid-chars = Username contains invalid characters. Use lowercase letters, numbers, dashes and underscores only.
# Error message shown on registration, when the username *does not match* any of the patterns that are allowed by the server policy.
coauth-errors-handle-not-allowed = Username is not allowed by the server policy
coauth-errors-handle-taken = This username is already taken
coauth-errors-handle-too-long = Username is too long
coauth-errors-handle-too-short = Username is too short
coauth-login-call-to-register = Don't have an account yet?
# Button to log in with an upstream provider
coauth-login-continue-with-provider = Continue with { $provider }
coauth-login-description = Please sign in to continue:
# On the login page, link to the account recovery process
coauth-login-forgot-password = Forgot password?
coauth-login-headline = Sign in
coauth-login-link-description = Linking your <span class="break-keep text-links">{ $provider }</span> account
coauth-login-link-headline = Sign in to link
coauth-login-no-login-methods = No login methods available.
coauth-login-handle-or-email = Username or Email
coauth-navbar-my-account = My account
coauth-navbar-register = Create an account
# Displayed in the navbar when the user is signed in
coauth-navbar-signed-in-as = Signed in as <span class="font-semibold">{ $handle }</span>.
coauth-not-found-description = The page you were looking for doesn't exist or has been moved
coauth-not-found-heading = Page not found
# Suggestions for the user to log in as a different user
coauth-not-you = Not { $handle }?
# Separator between the login methods
coauth-or-separator = Or
# Displayed when an authorization request is denied by the policy
coauth-policy-violation-description =
    This might be because of the client which authored the request, the currently logged in user, or the request itself.
# Displayed when an authorization request is denied by the policy
coauth-policy-violation-heading = The authorization request was denied by the policy enforced by this service
coauth-policy-violation-logged-as = Logged as <span class="font-semibold">{ $handle }</span>
# Description on the error page shown when a user tries to use a recovery link that has already been used
coauth-recovery-consumed-description = To create a new password, start over and select “Forgot password”.
# Title on the error page shown when a user tries to use a recovery link that has already been used
coauth-recovery-consumed-heading = The link to reset your password has already been used
coauth-recovery-disabled-description = If you have lost your credentials, please contact the administrator to recover your account.
coauth-recovery-disabled-heading = Account recovery is disabled
# Description on the page shown when a user tries to use an expired recovery link
coauth-recovery-expired-description = Request a new email that will be sent to: <span>{ $email }</span>.
# Title on the page shown when a user tries to use an expired recovery link
coauth-recovery-expired-heading = The link to reset your password has expired
coauth-recovery-expired-resend-email = Resend email
# Label for the password confirmation field
coauth-recovery-finish-confirm = Enter new password again
# Description for the final password recovery page
coauth-recovery-finish-description = Choose a new password for your account.
# Heading for the final password recovery page
coauth-recovery-finish-heading = Reset your password
# Label for the new password field
coauth-recovery-finish-new = New password
# Button to save the new password and continue
coauth-recovery-finish-save-and-continue = Save and continue
# Button to change the email address for the password recovery link
coauth-recovery-progress-change-email = Try a different email
# The description of the password recovery page, informing the user that an email has been sent to reset their password
coauth-recovery-progress-description =
    We sent an email with a link to reset your password if there's an account using <span>{ $email }</span>.
# The title of the password recovery page, informing the user that an email has been sent to reset their password
coauth-recovery-progress-heading = Check your email
# Button to resend the email with the password recovery link
coauth-recovery-progress-resend-email = Resend email
# The description of the page to initiate an account recovery
coauth-recovery-start-description = An email will be sent with a link to reset your password.
# The title of the page to initiate an account recovery
coauth-recovery-start-heading = Enter your email to continue
# Displayed on the registration page to suggest to log in instead
coauth-register-call-to-login = Already have an account?
coauth-register-continue-with-email = Continue with email address
coauth-register-continue-with-password = Continue with password
coauth-register-create-account-description = Choose a username to continue.
coauth-register-create-account-heading = Create an account
coauth-register-terms-of-service = I agree to the <a href="{ $tos_uri }" data-kind="primary" class="cpd-link">Terms and Conditions</a>
coauth-registration-token-description = Enter a registration token provided by your coauth administrator.
coauth-registration-token-field = Registration token
coauth-registration-token-headline = Registration token
coauth-scope-coauth-admin = Manage coauth accounts (urn:coauth:admin)
coauth-scope-send-messages = Send Cokret messages on your behalf
coauth-scope-view-messages = Read Cokret message metadata
# Displayed when the 'openid' scope is requested
coauth-scope-view-profile = See your coauth profile info and contact details
# Page shown when the user tries to link an upstream account that is already linked to another account
coauth-upstream-oauth-link-mismatch-heading = This upstream account is already linked to another account.
coauth-upstream-oauth-register-choose-handle-description = This cannot be changed later.
# Displayed when creating a new account from an SSO login, and the username is not forced
coauth-upstream-oauth-register-choose-handle-heading = Choose your username
# Displayed when creating a new account from an SSO login, and the username is pre-filled and forced
coauth-upstream-oauth-register-create-account = Create a new account
coauth-upstream-oauth-register-enforced-by-policy = Enforced by server policy
# Tells the user what display name will be imported
coauth-upstream-oauth-register-forced-display-name = Will use the following display name
# Tells the user which email address will be imported
coauth-upstream-oauth-register-forced-email = Will use the following email address
# Tells the user which username will be used
coauth-upstream-oauth-register-forced-handle = Will use the following username
coauth-upstream-oauth-register-import-data-description = Confirm the information that will be linked to your new { $server_name } account.
coauth-upstream-oauth-register-import-data-heading = Import your data
coauth-upstream-oauth-register-imported-from-upstream = Imported from your upstream account
coauth-upstream-oauth-register-imported-from-upstream-with-name = Imported from your { $human_name } account
# Button to link an existing account after an SSO login
coauth-upstream-oauth-register-link-existing = Link to an existing account
coauth-upstream-oauth-register-provider-name = { $human_name } account
coauth-upstream-oauth-register-signup-with-upstream-heading = Continue signing up with your { $human_name } account
# Option to let the user import their display name after an SSO login
coauth-upstream-oauth-register-suggested-display-name = Import display name
# Option to let the user import their email address after an SSO login
coauth-upstream-oauth-register-suggested-email = Import email address
coauth-upstream-oauth-register-use = Use
coauth-upstream-oauth-suggest-link-action = Link
coauth-upstream-oauth-suggest-link-heading = Link to your existing account
coauth-verify-email-6-digit-code = 6-digit code
coauth-verify-email-description = Enter the 6-digit code sent to: <em>{ $email }</em>
coauth-verify-email-headline = Verify your email
