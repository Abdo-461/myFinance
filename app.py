from flask import Flask, render_template, request, flash, redirect, url_for, json, session
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from random import randint
from datetime import date, datetime, timedelta
import requests
from decimal import Decimal
import boto3
import re
import os
from boto3.dynamodb.conditions import Key
from sendgrid.helpers.mail.from_email import From

github_blueprint = make_github_blueprint(
    scope=["email"],
    client_id=os.getenv("GITHUB_ID"),
    client_secret=os.getenv("GITHUB_SECRET"),
)

google_blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_ID"),
    client_secret=os.getenv("GOOGLE_SECRET"),
    scope=["profile", "email"]
)

# create dynamo object with access and secret keys
dynamodb = boto3.resource('dynamodb', aws_access_key_id=os.getenv("AWS_ID"),
                          aws_secret_access_key=os.getenv("AWS_KEY"),
                          region_name='us-east-1')

# s3 object to define s3 bucket
s3 = boto3.resource('s3', aws_access_key_id='',
                    aws_secret_access_key='',
                    region_name='us-east-1')
bucket = s3.Bucket('')

application = Flask(__name__)


# Login function --START--
@application.route("/", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # get user information from form
        email = request.form['email']
        password = request.form['password']
        # get table
        table = dynamodb.Table('users')
        # query table and comapre email
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(email)
        )
        # put results in items
        items = response['Items']
        for item in items:
            session['user_name'] = item['user_name']
            session['user_email'] = item['user_email']
            # comapre password
            if password == item['password']:
                return redirect(url_for('dashboard'))

        flash("Email or Password Invalid")
    return render_template('login.html')

# Login function --END--

# Register function --START--


@application.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Gather user information from register form
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        income = request.form['income']
        # Get the table
        table = dynamodb.Table('users')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(email)
        )
        items = response['Items']
        # If email doesn't exist add information to database table
        if not items:
            table.put_item(
                Item={
                    'user_email': email,
                    'user_name': name,
                    'income': income,
                    'password': password
                }
            )
            # Re-direct user to login page after registering
            flash('You have been successfully registered!')
            return render_template('login.html')

        flash("Email already Exists")
    return render_template('register.html')

# Register function --END--

# logout function --START--


@application.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('user_name', None)
    return redirect('/')

# logout function --END--

# Github Login function --START--


@application.route("/github")
def githubLogin():
    if not github.authorized:
        return redirect(url_for("github.login"))
    res = github.get("/user")
    if res.ok:
        oauth = github_blueprint.session.access_token
        account_info = res.json()
        session['user_name'] = account_info["name"]
        session['user_email'] = account_info["email"]
        # check if user is in the DB otherwise add email, password, oauth token
        table = dynamodb.Table('oauthusers')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(session['user_email'])
        )
        items = response['Items']
        # If email doesn't exist add information to database table
        if not items:
            table.put_item(
                Item={
                    'user_email': session['user_email'],
                    'user_name': session['user_name'],
                    'oauth_token': oauth
                }
            )
    # Update oauth token
    if response['Items'][0]['oauth_token'] != oauth:
        table.put_item(
            Item={
                'user_email': session['user_email'],
                'user_name': session['user_name'],
                'oauth_token': oauth
            }
        )
    # validate oauth token
    if oauth == response['Items'][0]['oauth_token']:
        return redirect(url_for('dashboard'))
# Github Login function --END--

# Google Login function --START--


@application.route("/google")
def googleLogin():
    if not google.authorized:
        return redirect(url_for("google.login"))
    res = google.get("/oauth2/v1/userinfo")
    if res.ok:
        oauth = google_blueprint.session.access_token
        account_info = res.json()
        session['user_name'] = account_info["name"]
        session['user_email'] = account_info["email"]
        # check if user is in the DB otherwise add email, password, oauth token
        table = dynamodb.Table('oauthusers')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(session['user_email'])
        )
        items = response['Items']
        # If email doesn't exist add information to database table
        if not items:
            table.put_item(
                Item={
                    'user_email': session['user_email'],
                    'user_name': session['user_name'],
                    'oauth_token': oauth
                }
            )
    # Update oauth token
    if response['Items'][0]['oauth_token'] != oauth:
        table.put_item(
            Item={
                'user_email': session['user_email'],
                'user_name': session['user_name'],
                'oauth_token': oauth
            }
        )
    # validate oauth token
    if oauth == response['Items'][0]['oauth_token']:
        return redirect(url_for('dashboard'))
# Google Login function --END--


@application.route("/dashboard")
def dashboard():
    return render_template('dashboard.html', username=session['user_name'])


@application.route("/credit", methods=["GET"])
def credit():
    return render_template('creditcheck.html', username=session['user_name'])


@application.route("/userprofile", methods=["GET"])
def userprofile():
    return render_template('userprofile.html', username=session['user_name'])


@application.route('/loans')
def loans():
    return render_template('loans.html', username=session['user_name'])
# send verification code function --START--


@application.route('/sendVerificationCode', methods=['POST', 'GET'])
def sendVerificationCode():
    if request.method == 'POST':
        email = request.form['email']
        session['user_email'] = email
        table = dynamodb.Table('users')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(email)
        )
        items = response['Items']
        # If email doesn't exist add information to database table
        if not items:
            flash('There are no accounts associated with this email!')
            return render_template('passwordReset.html')
        else:
            verifyCode = randint(000000, 999999)
            session['verify_code'] = verifyCode
            message = Mail(
                from_email=From('andrewgatty97@gmail.com', 'myFinance'),
                to_emails=email,
                subject='myFinance Password Reset',
                html_content=f'<strong>Your verification code is {verifyCode}. Please enter this in your browser to reset your password.</strong>')
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            response = sg.send(message)
            return redirect(url_for('passwordReset'))
    return render_template('passwordReset.html')
# send verification code function --END--

# password reset function --START--


@application.route('/passwordReset', methods=['POST', 'GET'])
def passwordReset():
    if request.method == 'POST':
        try:
            session['verify_code']
        except:
            flash('Please request a verfication code first!')
            return render_template('passwordReset.html')
        verifyCode = request.form['verifyCode']
        password = request.form['password']
        table = dynamodb.Table('users')
        if int(verifyCode) == session['verify_code']:
            response = table.update_item(
                Key={
                    'user_email': session['user_email']
                },
                UpdateExpression="set password = :p",
                ExpressionAttributeValues={
                    ':p': password,
                },
                ReturnValues="UPDATED_NEW"
            )
            session.pop('verify_code', None)
            return redirect(url_for('login'))
        else:
            flash('Invalid Verification Code!')
    return render_template('passwordReset.html')
# password reset function --END--

# password change function --START--


@application.route('/passwordChange', methods=['POST'])
def passwordChange():
    if request.method == 'POST':
        # get user information from form
        oldPassword = request.form['old-password']
        newPassword = request.form['new-password']
        # get table
        table = dynamodb.Table('users')
        # query table and comapare email
        response = table.query(
            KeyConditionExpression=Key('user_email').eq(session['user_email'])
        )
        # put results in items
        items = response['Items']
        for item in items:
            # compare password
            if oldPassword == item['password']:
                response = table.update_item(
                    Key={
                        'user_email': session['user_email'],
                        'user_name': session['user_name']
                    },
                    UpdateExpression="set password = :p",
                    ExpressionAttributeValues={
                        ':p': newPassword,
                    },
                    ReturnValues="UPDATED_NEW"
                )
                flash('Your Password has successfully been changed!')
                return redirect(url_for('userprofile'))

        flash("Old Password Incorrect")
    return redirect(url_for('userprofile'))
# password change function --END--

# Exchange rates function --START--


@application.route('/exchangeRates', methods=['POST', 'GET'])
def exchangeRates():
    if request.method == 'POST':
        try:
            request.form['currency']
        except:
            flash("An error has occured please select a currency and try again")
            return render_template('exchangeRates.html')
        currency = request.form['currency']
        currentDate = datetime.today()
        monthAgo = currentDate.month - 1
        currentDate = currentDate.strftime('%Y-%m-%d')
        lastMonth = datetime.today().replace(month=monthAgo).strftime('%Y-%m-%d')
        url = "https://5z68g150mc.execute-api.us-east-1.amazonaws.com/" + currency + \
            "?start_date=" + lastMonth + "&end_date=" + \
            currentDate + "&api_key=wq3dM8kdtTWZ3JoNUGdU"
        response = requests.get(url)
        rates = response.json()['dataset']['data']
        exchangeName = response.json()['dataset']['name']
        return render_template('exchangeRates.html', rates=rates, exchangeName=exchangeName, currentDate=currentDate, lastMonth=lastMonth)
    return render_template('exchangeRates.html')
# Exchange rates function --END--

# Credit check function --START--


# paid on time list - Loan
loanPaidOnTime = list()
# paid late list
loanPaidLate = list()

# paid on time list - Credit Card
cardPaidOnTime = list()
# paid late list
cardPaidLate = list()

# paid on time list - Bills
billPaidOnTime = list()
# paid late list
billPaidLate = list()


@application.route("/creditCheck")
def creditCheck():

    # loan repayment
    # refernce table
    loanTable = dynamodb.Table('LoanHistory')
    # query table
    loanResponse = loanTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    # put response in items variable
    loanItems = loanResponse['Items']
    # iterate through the items and compare paid off time with terms to determine loan payments health
    for loans in loanItems:
        if loans['paid_off_term'] <= loans['terms']:
            loanPaidOnTime.append(loans['loan_status'])
        elif loans['paid_off_term'] > loans['terms']:
            loanPaidLate.append(loans['loan_status'])
    # compare amount of on time and late payments and assign score
    if len(loanPaidOnTime) < len(loanPaidLate):
        loanScore = 150
    elif len(loanPaidOnTime) > len(loanPaidLate):
        loanScore = 300
    elif len(loanPaidOnTime) == len(loanPaidLate):
        loanScore = 260

    # credit card repayment
    # refernce table
    creditCardTable = dynamodb.Table('CreditCardPayments')
    # query table
    creditCardResponse = creditCardTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    # put items in items variable
    cardItems = creditCardResponse['Items']
    # iterate through the items and compare duration time with payment duration to determine credit card health
    for credit in cardItems:
        if credit['payment_duration'] <= credit['duration']:
            cardPaidOnTime.append(credit['status'])
        elif credit['payment_duration'] > credit['duration']:
            cardPaidLate.append(credit['status'])
    # compare amount of on time and late payments and assign score
    if len(cardPaidOnTime) < len(cardPaidLate):
        cardScore = 150
    elif len(cardPaidOnTime) > len(cardPaidLate):
        cardScore = 300
    elif len(cardPaidOnTime) == len(cardPaidLate):
        cardScore = 260

    # bills payment
    # reference table
    billsPaymentTable = dynamodb.Table('BillsPayment')
    # query table
    billsResponse = billsPaymentTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    # put items in items variable
    billItems = billsResponse['Items']
    # iterate through the items and compare duration time with payment duration to determine credit card health
    for bills in billItems:
        if bills['pay_on_time'] == 'YES':
            billPaidOnTime.append(bills['pay_on_time'])
        billPaidLate.append(bills['pay_on_time'])
    # compare amount of on time and late payments and assign score
    if len(billPaidOnTime) < len(billPaidLate):
        billScore = 150
    elif len(billPaidOnTime) > len(billPaidLate):
        billScore = 300
    elif len(billPaidOnTime) == len(billPaidLate):
        billScore = 260

    # calculate total credit score
    creditScore = loanScore + cardScore + billScore
    # show analysis of credit score
    if 400 <= creditScore <= 500:
        message = 'Your Credit Score is very low.'
    elif 550 <= creditScore <= 700:
        message = 'You have a healthy credit. Could be better.'
    elif creditScore > 700:
        message = 'You have excellent credit!'

    return render_template('creditcheck.html', loanScore=loanScore, cardScore=cardScore, billScore=billScore, creditScore=creditScore, message=message, username=session['user_name'])

# Credit Check function --END--

# Save Credit Score function --START--

# save credit score to database


@application.route('/saveCredit', methods=["POST"])
def saveCredit():
    if request.method == 'POST':
        # fetch credit score
        creditScore = request.form['creditscore']
        # referene table
        creditScoreTable = dynamodb.Table('CreditScores')
        # validate if input is empty
        if creditScore is None:
            flash('You need to check your credit first')
            return redirect(url_for('credit'))

        creditScoreTable.put_item(
            Item={
                'user_email': session['user_email'],
                'credit_score': creditScore
            }
        )
    flash("Score Saved!")
    return redirect(url_for('creditCheck'))

# Save credit score function --end--


# check elligble loans function --START--
global elgibleLoan


@application.route('/eligibleLoans')
def eligibleLoans():
    # refernece credit table
    creditTable = dynamodb.Table('CreditScores')
    # query credit table to fetch user's credit score
    creditScoreResponse = creditTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    # put response in item variable
    creditScoresItems = creditScoreResponse['Items']

    # create variable for credit score
    for creditScoreLoans in creditScoresItems:
        creditScore = creditScoreLoans['credit_score']

    # refernce loan table
    eligibleLoanTable = dynamodb.Table('EligibleLoans')
    # query table to fetch loans depending on user's credit score
    eligibleLoanResponse = eligibleLoanTable.query(
        IndexName='credit_score_Index',
        KeyConditionExpression=Key('min_cs').eq(creditScore)
    )
    # put items in Item variable
    loanItems = eligibleLoanResponse["Items"]
    if not loanItems:
        flash("Sorry, you are not eligible for any loans")

    return render_template('loans.html', elgibleLoan=loanItems, username=session['user_name'])
# check elligble loans function --END--

# calculat interest rate function --START--


interestToPay = None


@application.route('/checkRate', methods=['GET', 'POST'])
def checkRate():
    if request.method == 'POST':
        # fetch info given by user
        loanID = request.form['loanid']
        payments = request.form['payments']
        # reference ytable
        eligibleLoansTable = dynamodb.Table('EligibleLoans')
        # query table to get interest rate
        response = eligibleLoansTable.query(
            KeyConditionExpression=Key('loan_id').eq(loanID)
        )
        # put response in items variable
        items = response['Items']
        # get rate and loan amount
        interestRate = items[0]['interest_rate']
        loanPrinciple = items[0]['loan_amount']
        # calculate interest to paid
        interestToPay = interestRate / Decimal(payments) * loanPrinciple

    return render_template('loans.html', paidInterest=round(interestToPay))

# calculat interest rate function --END--


application.secret_key = 'super secret key'
application.config['SESSION_TYPE'] = 'filesystem'
application.register_blueprint(github_blueprint, url_prefix="/login")
application.register_blueprint(google_blueprint, url_prefix="/login")

if __name__ == '__main__':
    application.run(port=8000, debug=True)
