from os import access
from flask import Flask, render_template, redirect, send_file, url_for, request, session, make_response
import requests
import boto3
import json
from werkzeug.utils import secure_filename
import random as rand
import string as string
import time
import urllib
import os
from config import Config
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.config.from_object(Config)

# Remember to also paste these values into the lambda functions
access_key_id = "Update From Lab Session"
secret_access_key = "Update From Lab Session"
session_token = "Update From Lab Session"
region = "us-east-1"

# Secret Key for Session
app.secret_key = "SecretKeyOOOOO"

BUCKET_NAME = "s3873735-a3-profile-images"

print("working...")

client = boto3.client(
    'dynamodb',
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key,
    aws_session_token=session_token,
    region_name=region
)

s3 = boto3.client(
    's3',
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key,
    aws_session_token=session_token,
    region_name=region
)

dynamodb = boto3.resource(
    'dynamodb', 
    aws_access_key_id=access_key_id, 
    aws_secret_access_key=secret_access_key,
    aws_session_token=session_token,
    region_name=region)

def createStateKey(size):
	#https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits
	return ''.join(rand.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))

def getToken(code):
    token_url = 'https://accounts.spotify.com/api/token'
    authorization = app.config['AUTHORIZATION']
    redirect_uri = app.config['REDIRECT_URI']
    print("Authorization: " + authorization)
    print("GetToken Code: " + code)

    headers = {
        'Authorization': authorization,
        'Content-Type': 'application/x-www-form-urlencoded'}
    body = {
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'}

    post_response = requests.post(token_url, headers=headers, data=body)
    print("POST_RESPONSE BELOW: ")
    print("")
    print(post_response.text)
    print("_")

    if post_response.status_code == 200:
        pr = post_response.json()
        return pr['access_token'], pr['refresh_token'], pr['expires_in']
    else:
        print('getToken:' + str(post_response.status_code))
        return None

def refreshToken(refresh_token):
    token_url = 'https://accounts.spotify.com/api/token'
    authorization = app.config['AUTHORIZATION']

    headers = {
        'Authorization' : authorization,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'}
    body = {
        'refresh_token': refresh_token, 'grant_type': 'refresh_token'}
    post_response = requests.post(token_url, headers=headers, data=body)

    if post_response.status_code == 200:
        return post_response.json()['access_token'], post_response.json()['expires_in']
    else:
        print('refresh Token' + str(post_response.status_code))
        return None

def getTrackInformation(track_id):
    if session.get('token') == None or session.get('token_expiration') == None:
        print("token, or token time remaining is 'NONE' redirecting...")
        return redirect('authorize')
    
    authorization = 'Bearer ' + session['token']
    get_track_url = 'https://api.spotify.com/v1/tracks/' + track_id

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': authorization
    }
    response = requests.get(url=get_track_url, headers=headers)
    return response

def getRecommendations(track_id):
    recommendation_list = []

    if session.get('token') == None or session.get('token_expiration') == None:
        return redirect('authorize')

    authorization = 'Bearer ' + session['token']

    url = "https://api.spotify.com/v1/recommendations?limit=20&market=ES&seed_tracks=" + track_id

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': authorization
    }

    get_response = requests.get(url=url, headers=headers).json()

    print("Get_Response in Recommendations below")
    
    get_response = get_response['tracks']

    for response in get_response:
        track_info = {
            'uri' : response['uri'],
            'name' : response['name'],
            'artist' : response['artists'][0]['name'],
            'image_url' : response['album']['images'][2]['url']
        }
        
        recommendation_list.append(track_info)
        
    return recommendation_list

def checkTokenStatus(session):
    if time.time() > session['token_expiration']:
        pload = refreshToken(session['refresh_token'])
    
    if pload != None:
        session['token'] = pload[0]
        session['token_expiration'] = time.time() + pload[1]
    else:
        print('checkTokenStatus')
        return None
    
    return "Success"


def makeGetRequest(session, url, params={}):
    headers = {"Authorization": "Bearer {}".format(session['token'])}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401 and checkTokenStatus(session) != None:
        return makeGetRequest(session, url, params)
    else:
        print('makeGetRequest:' + str(response.status_code))
        return None

def getUserInformation(session):
    url = 'https://api.spotify.com/v1/me'
    payload = makeGetRequest(session, url)

    if payload == None:
        return None

    return payload


@app.route('/', methods=['GET', 'POST'])
def root():
    error = ""

    return render_template('index.html', error=error)

@app.route('/authorize')
def authorize():
    print("Authorize has been called")
    client_id = app.config['CLIENT_ID']
    client_secret = app.config['CLIENT_SECRET']
    redirect_uri = app.config['REDIRECT_URI']
    scope = app.config['SCOPE']

    state_key = createStateKey(15)
    session['state_key'] = state_key

    authorize_url = 'https://accounts.spotify.com/en/authorize?'
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state_key
    }

    query_params = urllib.parse.urlencode(params)
    print("query_params: " + query_params)
    print("auth url: " + authorize_url + query_params)
    response = make_response(redirect(authorize_url + query_params))

    return response

@app.route('/callback')
def callback():
    # make sure response from spotify
    if request.args.get('state') != session['state_key']:
        return render_template('index.html', error='State failed.')
    if request.args.get('error'):
        return render_template('index.html', error='Spotify Error')

    else:
        code = request.args.get('code')
        print("this is the request artsg get code")
        print(code)
        session.pop('state_key', None)

        # get access token to make requests on behalf of the user.
        payload = getToken(code)
        if payload != None:
            session['token'] = payload[0]
            session['refresh_token'] = payload[1]
            session['token_expiration'] = time.time() + payload[2]
            print(session['token_expiration'])
        else:
            print(payload)
            return render_template('index.html', error='Failed to access token')

    current_user = getUserInformation(session)
    session['user_id'] = current_user['id']
    print('new user: '+ session['user_id'])

    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # This will query the db for the user provided email only
        response = client.get_item(
            TableName='login',
            Key={
                'email': { 'S': email }
            }
        )
        # If the email exists in the dynamo db. 'Item' will exist in response
        # so this basically says valid email address
        if 'Item' in response:
            item = response['Item']
            correct_pass = item['password']['S']
            if password != correct_pass:
                error += " Incorrect Password."
            else:
                print("load home")
                session['email'] = email
                session['username'] = item['username']['S']
                #Remove These
                print(item)
                print(item['password']['S'])
                return redirect(url_for('home'))
                
        else:
            error += " This email address does not exist."


    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ""

    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        #Query user inputted email
        response = client.get_item(
            TableName='login',
            Key={
                'email': { 'S': email }
            }
        )
        #Check if email already exists
        if 'Item' in response:
            error += " The email already exists."
        else:
            client.put_item(
                TableName='login',
                Item= {
                    'email' : {'S' : email},
                    'password' : {'S' : password},
                    'username' : {'S' : username}
                }
            )
            error="Registration Successful. Please login"
            return redirect(url_for('login', error=error))
        
    return render_template('register.html', error=error)

@app.route('/home', methods=['GET', 'POST'])
def home():
    email = session['email']
    username = session['username']
    username_friendly = username.replace(' ', '+') + ".jpg"
    profile_image_url = "https://s3873735-a3-profile-images.s3.amazonaws.com/" + username_friendly
    recommendations = []
    print("home")

    print("Session Information Below")
    print("")
    print(session)
    print("-----------------------------------------------------")
   
    
    # figure out the uhhhh API Gateway calls...
    payload = {"email" : email}
    headers = {"Content-Type": "application/json"}
    URL = "https://c5aqxpsqse.execute-api.us-east-1.amazonaws.com/RecommendationsDev/userrecommendations"
    recommendationList = requests.request("GET", URL, params=payload, headers=headers)
    print(recommendationList.text)

    recent_search_list = requests.request("POST", URL, params=payload, headers=headers)
    search_list = []
        
    # Modify data for recent search list to use in html template
    print("heres the recent_search_list yo")
    print(recent_search_list.json())
    url_search_list = recent_search_list.json()

    # Here we will figure out how to use get Track from spotify web api
    # Example URL that we need to string manip: https://open.spotify.com/track/0TpJF2IIk9idRMJuSSXMLh?si=055f020b984843e5
    if session.get('token') != None:
        for search in url_search_list:
            # Need to get everything before the ? and everything after the last /
            song_url = search['link_address']['S']
            song_url_trimmed = song_url.split('?', 1)[0]
            song_id = song_url_trimmed.split('/')[-1]
            track_info = getTrackInformation(song_id).json()
            if 'error' in track_info:
                return(redirect('authorize'))
            else: 
                print("Track link: " + track_info['uri'])
                print('Name: ' + track_info['name'])
                track_link = track_info['uri']
                track_name = track_info['name']
                artist_name = track_info['album']['artists'][0]['name']
                search_list.append({
                    'track_link' : track_link,
                    'track_name': track_name,
                    'artist_name': artist_name
                })
    else:
        return redirect('authorize')
     
    # From Here we can get the reccomendation list based on the most Recent song
    # That has been added to the list (Authorization should already have beeen checked by now)
    if url_search_list != []:
        most_recent_song = url_search_list[0]['link_address']['S'].split('?', 1)[0].split('/')[-1]
        recommendations = getRecommendations(most_recent_song)

    return render_template('home.html', email=email, username=username, search_list=search_list, recommendations=recommendations, profile_image_url=profile_image_url)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    email = session['email']
    username = session['username']
    msg = ""

    username_friendly = username.replace(' ', '+') + ".jpg"
    profile_image_url = "https://s3873735-a3-profile-images.s3.amazonaws.com/" + username_friendly


    return render_template('profile.html', email=email, username=username, msg=msg, profile_image_url=profile_image_url)


@app.route('/upload', methods=['POST'])
def upload():
    email = session['email']
    username = session['username']
    msg=""

    if request.method == 'POST':
        img = request.files['file']
        if img:
            filename = username + ".jpg"
            img.save(filename)
            s3.upload_file(
                Bucket = BUCKET_NAME,
                Filename=filename, 
                Key = filename
            )
            msg = "Upload Complete!"
            os.remove(filename)


    return redirect(url_for('profile', email=email, username=username, msg=msg))

@app.route('/addsong', methods=['GET', 'POST'])
def addsong():

    email = session['email']
    username = session['username']

    # add the users inputted link to dynamoDB
    # 1. obtain the song link from the form on submit
    if request.method == 'POST' and request.form['song-input'] != "":
        song_link = request.form['song-input']

        # 2. Ensure that the combination doesn't already exist
        response = client.get_item(
            TableName='entered_song_links',
            Key={
                'user_email' : {'S' : email},
                'link_address' : {'S' : song_link}
            }
        )

        print(response)

        if 'Item' in response:
            return redirect(url_for('home', email=email, username=username))
            print("this song has already been searched by user.")

        # if the combo doesn't already exist. place the value in dynamodb
        else:
            client.put_item(
                TableName='entered_song_links',
                Item={
                    'user_email' : {'S' : email},
                    'link_address' : {'S' : song_link}
                }
            )
            print("the item has been placed in dynamodb")

    return redirect(url_for('home', email=email, username=username))

    


    
    
    

