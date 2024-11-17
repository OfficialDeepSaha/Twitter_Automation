CHROMEDRIVER_PATH= "C:/chromedriver-win64/chromedriver.exe"
CHROME_PROFILE_PATH = "C:/Users/DEEP SAHA/AppData/Local/Google/Chrome/User Data/Default"
TWITTER_CLIENT_ID = "hmqwSfcYqAvRfxgNZPchAoLVZ"
TWITTER_CLIENT_SECRET = "r5RlXNFAvS4z3W4ZUYXNw1IHZDWLyip6leGRbpV1fBl2h9fhH9"
TWITTER_CALLBACK_URL = "https://ultimate-connector.vercel.app/auth/twitter/callback"
TWITTER_SIGNUP_CALLBACK_URL = "https://ultimate-connector.vercel.app/auth/signup/twitter/callback"




@app.get("/api/twitter/signup/register")
async def twitter_register():
    oauth = OAuth1Session(
        TWITTER_CLIENT_ID,
        client_secret=TWITTER_CLIENT_SECRET,
        callback_uri=TWITTER_SIGNUP_CALLBACK_URL
    )

    try:
        # Step 1: Fetch the request token
        request_token_url = "https://api.twitter.com/oauth/request_token"
        response = oauth.fetch_request_token(request_token_url)
        oauth_token = response.get('oauth_token')
        if not oauth_token:
            raise HTTPException(status_code=400, detail="Failed to get request token")

        # Step 2: First authorization request to Twitter
        twitter_auth_url = f"https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}"
        async with httpx.AsyncClient() as client:
            first_response = await client.get(twitter_auth_url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            })
            first_cookies = first_response.cookies
            print("First Call Cookies:", first_cookies)
           

        return {"auth_url": twitter_auth_url, "first_call_cookies": first_cookies}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error during Twitter OAuth: {str(e)}")


def get_chrome_profile_path():
    """Dynamically detects the Chrome profile path based on the user's operating system."""
    system = platform.system()
    print(system)
    processor = platform.processor()
    print(processor)
    # Path for Windows
    if system == "Windows":
        # Typically, the path is something like this for Windows
        user_profile_path = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default")
        return user_profile_path
    
    # Path for macOS
    elif system == "Darwin":
        # Typical path for macOS
        user_profile_path = os.path.expanduser("~/Library/Application Support/Google/Chrome")
        return os.path.join(user_profile_path, "Default")

    # Path for Linux
    elif system == "Linux":
        # Typical path for Linux
        user_profile_path = os.path.expanduser("~/.config/google-chrome")
        return os.path.join(user_profile_path, "Default")

    else:
        raise ValueError(f"Unsupported OS: {system}")




@app.get("/api/auth/twitter/callback")
async def twitter_callback(oauth_token: str, oauth_verifier: str, db: Session = Depends(get_db)):
    oauth = OAuth1Session(TWITTER_CLIENT_ID, client_secret=TWITTER_CLIENT_SECRET)
    
    try:
        # Obtain access token from Twitter
        access_token_url = "https://api.twitter.com/oauth/access_token"
        token_data = {"oauth_token": oauth_token, "oauth_verifier": oauth_verifier}
        print("Token Data:- " , token_data)
        response = oauth.post(access_token_url, params=token_data)
        print("Token Response:- " , response.headers.get('set-cookie' , ''))
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch access token from Twitter")

        # Parse access token
        credentials = dict(item.split("=") for item in response.text.split("&"))
        access_token = credentials.get("oauth_token")
        access_token_secret = credentials.get("oauth_token_secret")
        print("Access Token:- " , access_token)
        print("Access Token Secret:- ", access_token_secret)

        # Verify user credentials using OAuth session
        oauth = OAuth1Session(
            TWITTER_CLIENT_ID,
            client_secret=TWITTER_CLIENT_SECRET,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret
        )
        
        
        verify_credentials_url = "https://api.twitter.com/1.1/account/verify_credentials.json"
        user_info_response = oauth.get(verify_credentials_url, params={"include_email": "true"})
        

        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user info from Twitter")

        user_info = user_info_response.json()
        print("User Info Response:- " , user_info)
        
        # # Define user_email and twitter_id from user_info response
        user_email = user_info.get("email")
        twitter_id = user_info.get("id_str")
        
        
        # Check if email is available
        if not user_email:
            raise HTTPException(status_code=400, detail="Email not available from Twitter.")

        # Set up Chrome options for Selenium and Xvfb
        chrome_options = Options()
        chrome_path= get_chrome_profile_path()
        chrome_options.add_argument(f"user-data-dir={chrome_path}")  # Using custom profile
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.binary_location = "/usr/bin/google-chrome-stable"
        chrome_options.add_argument("start-maximized")

        
        
        with webdriver.Chrome(options=chrome_options) as driver:
                # Switch to a new tab and open x.com/home
                driver.execute_script("window.open('');")  # Open a new tab
                driver.switch_to.window(driver.window_handles[-1])  # Switch to the new tab
                driver.get("https://x.com/home")
                
                try:
                    WebDriverWait(driver, 10).until(lambda d: "x.com/home" in d.current_url)
                    time.sleep(10)
                except Exception as e:
                    print(f"User is not logged in. Attempting to log in... Error: {str(e)}")
                    driver.get("https://x.com/i/flow/login")
                    WebDriverWait(driver, 1200).until(EC.presence_of_element_located((By.NAME, "text")))
                    print("Please log in to your Twitter account...")
                    WebDriverWait(driver, 1200).until(EC.url_contains("x.com/home"))

                # Fetch cookies after ensuring the user is logged in
                cookies = driver.get_cookies()
                csrf_token = next((cookie['value'] for cookie in cookies if 'ct0' in cookie['name']), None)
                auth_token = next((cookie['value'] for cookie in cookies if 'auth_token' in cookie['name']), None)

                if csrf_token is None or auth_token is None:
                    raise HTTPException(status_code=400, detail="Failed to retrieve necessary cookies")

        # Process user data and handle database logic
        existing_user = db.query(User).filter(User.email == user_email).first()
        if existing_user:
            # Generate JWT and response for existing user
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            jwt_token = create_access_token(data={"sub": existing_user.email}, expires_delta=access_token_expires)

            formatted_cookies = [{"name": c.get("name"), "value": c.get("value")} for c in cookies]
            return {
                "csrf_token": csrf_token,
                "auth_token": auth_token,
                "cookies": json.dumps(formatted_cookies, indent=2),
                "twitter_id": twitter_id,
                "access_token": jwt_token,
                "token_type": "bearer",
                "user": {"id": existing_user.id, "email": existing_user.email, "name": existing_user.name, "bio": existing_user.bio}
            }

        # Handle registration for new user
        new_user = User(
            email=user_email,
            name=user_info.get("screen_name"),
            bio=user_info.get("description", ""),
            twitter_handle=user_info.get("screen_name"),
            twitter_id=twitter_id,
            password=None
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Generate JWT for new user
        jwt_token = create_access_token(data={"sub": new_user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

        formatted_cookies = [{"name": c.get("name"), "value": c.get("value")} for c in cookies]
        return {
            "csrf_token": csrf_token,
            "auth_token": auth_token,
            "cookies": json.dumps(formatted_cookies, indent=2),
            "twitter_id": twitter_id,
            "access_token": jwt_token,
            "token_type": "bearer",
            "user": {"id": new_user.id, "email": new_user.email, "name": new_user.name, "bio": new_user.bio}
        }

    except Exception as e:
        print(f"Error during Twitter callback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

