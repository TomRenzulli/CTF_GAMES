FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything
COPY . .

# Generate static challenge files (writes to /app/challenge_files)
RUN python challenge_files/generate.py

# Place flag for challenge 18 (command injection)
RUN echo "FLAG{shell_metacharacters_execute_commands}" > /flag18.txt

EXPOSE 9300

CMD ["python", "app.py"]
