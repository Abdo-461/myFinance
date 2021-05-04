from flask import Flask, render_template , request, flash , redirect , url_for , json , session
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

@application.route("/")
def dashboard():
    return render_template('dashboard.html')




if __name__ == '__main__':
    application.run(debug=True)