from flask import Flask, render_template, request, flash, redirect, url_for, json, session
import boto3
import re
import os
from boto3.dynamodb.conditions import Key

# create dynamo object with access and secret keys
dynamodb = boto3.resource('dynamodb', aws_access_key_id='',
                          aws_secret_access_key='',
                          region_name='us-east-1')

# s3 object to define s3 bucket
s3 = boto3.resource('s3', aws_access_key_id='',
                    aws_secret_access_key='',
                    region_name='us-east-1')
bucket = s3.Bucket('')

application = Flask(__name__)


@application.route("/", methods=['POST', 'GET'])
@application.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # Gather the user information from the sign in form
        email = request.form['email']
        password = request.form['password']
        # Get the table
        table = dynamodb.Table('login')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        items = response['Items']
        session['email'] = items[0]['email']
        session['name'] = items[0]['name']
        # Check password is correct
        if password == items[0]['password']:
            return redirect(url_for('dashboard'))

        flash("Email or Password Invalid")
    return render_template('login.html')


@application.route("/dashboard")
def dashboard():
    if session.get('email'):
        return render_template('dashboard.html', name=session['name'])
    else:
        return redirect('/login')

@application.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('name', None)
    return redirect('/')


@application.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Gather user information from register form
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        # Get the table
        table = dynamodb.Table('login')
        # Query table to see if email exists
        response = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        items = response['Items']
        # If email doesn't exist add information to database table
        if not items:
            table.put_item(
                Item={
                    'email': email,
                    'name': name,
                    'password': password
                }
            )
            # Re-direct user to login page after registering
            flash('You have been successfully registered!')
            return render_template('login.html')

        flash("Email already Exists")
    return render_template('register.html')


application.secret_key = os.urandom(24)
application.config['SESSION_TYPE'] = 'filesystem'


if __name__ == '__main__':
    application.run(debug=True)
