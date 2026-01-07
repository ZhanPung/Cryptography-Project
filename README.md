# Applied Cryptography Group 5

## `.gitignore` Matters
- Ensure that the .gitignore contains the following:
  ```
    # Ignore Python virtual environment
    venv/

    # Ignore Python cache files
    __pycache__/
    
    # Ignore system files
    .DS_Store
    Thumbs.db
    /.idea
    
    # Ignore sensitive keys
    /config/key.key
    /config/config.encrypted
  ```

## How to Run
1. Set up a virtual environment and install dependencies:
      ```bash
      python -m venv venv
         > source venv/bin/activate (For MAC OS)
         > .\venv\Scripts\Activate (For Windows)
      pip install -r requirements.txt
      ```

2. Run server.py via CMD
    ```bash
    py server.py
    ```

3. Run instances of client.py via CMD
    ```bash
    py client.py
    ```
   
## First Time Setup
1.  In server.py, replace the following with your firebase configuration details. Save and execute the program. This will create the necessary directory trees, make sure you only run the program after replacing the firebaseConfig as shown below. 
    
    <br>_Note: If you accidentally ran the file without replacing the firebaseConfig, either re-clone from Git, or set the flag to 'false' in firstTimeSetup.txt, replace firebaseConfig accordingly, and run server.py again._ 
    
    ```
    ## Replace this accordingly and remove it thereafter
    
    firebaseConfig = {
    "apiKey": "your-api-key",
    "authDomain": "your-project.firebaseapp.com",
    "databaseURL": "https://your-project.firebaseio.com",
    "projectId": "your-project-id",
    "storageBucket": "your-project.appspot.com",
    "messagingSenderId": "your-sender-id",
    "appId": "your-app-id"
    }

## Dependencies
```
- Pyrebase4 >= 4.8.0
- cryptography >= 44.0.0
- bcrypt >= 4.2.1
- python-socketio >= 5.12.1
- aiohttp >= 3.11.12
- websocket-client >= 1.8.0
- phe >= 1.4.0
- setuptools >= 75.0.0
```
