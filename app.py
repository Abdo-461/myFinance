from flask import Flask, render_template, request, flash , redirect , url_for , json , session
from decimal import Decimal
import boto3
import re
from boto3.dynamodb.conditions import Key


#create dynamo object with access and secret keys
dynamodb = boto3.resource('dynamodb',aws_access_key_id='',
                                     aws_secret_access_key='',
                                     region_name='us-east-1')

#s3 object to define s3 bucket
s3 = boto3.resource('s3', aws_access_key_id='',
                          aws_secret_access_key='',
                          region_name='us-east-1')
bucket = s3.Bucket('')

application = Flask(__name__)


#Login function --START--
@application.route("/", methods=['POST', 'GET'])
def login():
    if request.method=='POST':
        #get user information from form
        email = request.form['email']
        password = request.form['password']
        #get table
        table = dynamodb.Table('users')
        #query table and comapre email
        response = table.query(
                KeyConditionExpression=Key('user_email').eq(email)
        )
        #put results in items
        items = response['Items']
        for item in items:
            session['user_name'] = item['user_name']
            session['user_email'] = item['user_email']
            #comapre password
            if password == item['password']:
                return redirect(url_for('dashboard'))

        flash("Email or Password Invalid")
    return render_template('login.html')

#Login function --END--

#Register function --START--
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
                    'income':income,
                    'password': password
                }
            )
            # Re-direct user to login page after registering
            flash('You have been successfully registered!')
            return render_template('login.html')

        flash("Email already Exists")
    return render_template('register.html')

#Register function --END--

#logout function --START--
@application.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('name', None)
    return redirect('/')

#logout function --END--


@application.route("/dashboard")
def dashboard():
    return render_template('dashboard.html', username=session['user_name'])


@application.route("/credit" , methods=["GET"])
def credit():
    return render_template('creditcheck.html', username=session['user_name'])

@application.route("/userprofile")
def userprofile():
    return render_template('userprofile.html')

@application.route('/loans')
def loans():
    return render_template('loans.html', username=session['user_name'])


#Credit check function --START--

#paid on time list - Loan
loanPaidOnTime=list()
#paid late list
loanPaidLate=list()

#paid on time list - Credit Card
cardPaidOnTime=list()
#paid late list
cardPaidLate=list()

#paid on time list - Bills
billPaidOnTime=list()
#paid late list
billPaidLate=list()
@application.route("/creditCheck")
def creditCheck():

    #loan repayment
    #refernce table
    loanTable = dynamodb.Table('LoanHistory')
    #query table
    loanResponse = loanTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    #put response in items variable
    loanItems = loanResponse['Items']
    #iterate through the items and compare paid off time with terms to determine loan payments health
    for loans in loanItems:
        if loans['paid_off_term'] <= loans['terms']:
            loanPaidOnTime.append(loans['loan_status'])
        elif loans['paid_off_term'] > loans['terms']:
            loanPaidLate.append(loans['loan_status'])
    #compare amount of on time and late payments and assign score
    if len(loanPaidOnTime) < len(loanPaidLate):
        loanScore=150
    elif len(loanPaidOnTime) > len(loanPaidLate):
        loanScore=300
    elif len(loanPaidOnTime) == len(loanPaidLate):
        loanScore=260

    #credit card repayment
    #refernce table
    creditCardTable = dynamodb.Table('CreditCardPayments')
    #query table
    creditCardResponse = creditCardTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    #put items in items variable
    cardItems = creditCardResponse['Items']
    #iterate through the items and compare duration time with payment duration to determine credit card health
    for credit in cardItems:
        if credit['payment_duration'] <= credit['duration']:
            cardPaidOnTime.append(credit['status'])
        elif credit['payment_duration'] > credit['duration']:
            cardPaidLate.append(credit['status'])
    #compare amount of on time and late payments and assign score
    if len(cardPaidOnTime) < len(cardPaidLate):
        cardScore=150
    elif len(cardPaidOnTime) > len(cardPaidLate):
        cardScore=300
    elif len(cardPaidOnTime) == len(cardPaidLate):
        cardScore=260

    #bills payment
    #reference table
    billsPaymentTable = dynamodb.Table('BillsPayment')
    #query table
    billsResponse = billsPaymentTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    #put items in items variable
    billItems = billsResponse['Items']
    #iterate through the items and compare duration time with payment duration to determine credit card health
    for bills in billItems:
        if bills['pay_on_time'] == 'YES':
            billPaidOnTime.append(bills['pay_on_time'])
        billPaidLate.append(bills['pay_on_time'])
    #compare amount of on time and late payments and assign score
    if len(billPaidOnTime) < len(billPaidLate):
        billScore=150
    elif len(billPaidOnTime) > len(billPaidLate):
        billScore=300
    elif len(billPaidOnTime) == len(billPaidLate):
        billScore=260

    #calculate total credit score
    creditScore = loanScore + cardScore + billScore
    #show analysis of credit score
    if 400 <= creditScore <= 500:
        message='Your Credit Score is very low.'
    elif 550 <= creditScore <= 700:
        message='You have a healthy credit. Could be better.'
    elif creditScore > 700:
        message='You have excellent credit!'

    return render_template('creditcheck.html' , loanScore = loanScore , cardScore = cardScore,billScore = billScore, creditScore = creditScore, message = message, username=session['user_name'])

#Credit Check function --END--

#Save Credit Score function --START--

#save credit score to database
@application.route('/saveCredit' , methods=["POST"])
def saveCredit():
 if request.method=='POST':
    #fetch credit score
    creditScore = request.form['creditscore']
    #referene table
    creditScoreTable = dynamodb.Table('CreditScores')
    #validate if input is empty
    if creditScore is None:
        flash('You need to check your credit first')
        return redirect(url_for('credit'))

    creditScoreTable.put_item(
        Item={
            'user_email':session['user_email'],
            'credit_score':creditScore
        }
    )
 flash("Score Saved!")
 return redirect(url_for('creditCheck'))

#Save credit score function --end--

#check elligble loans function --START--

@application.route('/eligibleLoans')
def eligibleLoans():

    #refernece credit table
    creditTable = dynamodb.Table('CreditScores')
    #query credit table to fetch user's credit score
    creditScoreResponse = creditTable.query(
        KeyConditionExpression=Key('user_email').eq(session['user_email'])
    )
    #put response in item variable
    creditScoresItems = creditScoreResponse['Items']

    #create variable for credit score
    for creditScoreLoans in creditScoresItems:
      creditScore = creditScoreLoans['credit_score']

    #refernce loan table
    eligibleLoanTable = dynamodb.Table('EligibleLoans')
    #query table to fetch loans depending on user's credit score
    eligibleLoanResponse = eligibleLoanTable.query(
        IndexName = 'credit_score_Index',
        KeyConditionExpression=Key('min_cs').eq(creditScore)
    )
    #put items in Item variable
    loanItems = eligibleLoanResponse["Items"]
    if not loanItems:
        flash("Sorry, you are not eligible for any loans")

    return render_template('loans.html', elgibleLoan = loanItems)


#check elligble loans function --END--


application.secret_key = 'super secret key'
application.config['SESSION_TYPE'] = 'filesystem'

if __name__ == '__main__':
    application.run(port=8000,debug=True)
