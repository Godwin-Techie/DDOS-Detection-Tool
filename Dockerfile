# --- Step 1: The Base Image ---
# This tells Docker to start with a lightweight version of Python 3.11.
# 'slim' means it doesn't include unnecessary files, making the container smaller and faster.
FROM python:3.11-slim

# --- Step 2: The Working Directory ---
# This creates a folder named '/app' inside the container.
# All following commands will happen inside this folder.
WORKDIR /app

# --- Step 3: Installing Dependencies ---
# We copy the 'requirements.txt' file from your computer into the container first.
# This file is just a list of the libraries we need (like Flask, requests, etc.).
COPY detector/requirements.txt requirements.txt

# This runs the 'pip install' command to actually download those libraries.
# '--no-cache-dir' keeps the container clean by not saving the temporary download files.
RUN pip install --no-cache-dir -r requirements.txt

# --- Step 4: Copying the Code ---
# Now we copy all your Python scripts from your 'detector/' folder on your computer 
# into the '/app/detector/' folder inside the container.
COPY detector/ /app/detector/

# --- Step 5: The Starting Command ---
# This is what happens when the container turns on.
# 'python -u' runs Python in "unbuffered" mode, which means it prints logs 
# to your screen immediately so you can see alerts in real-time.
# It targets 'main.py' to start the whole system.
CMD ["python", "-u", "detector/main.py"]