FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd -m ctfuser

# Copy everything
COPY . .

# Generate static challenge files (writes to /app/challenge_files)
RUN python challenge_files/generate.py

# Place flag for challenge 18 (command injection)
RUN echo "FLAG{shell_metacharacters_execute_commands}" > /flag18.txt

EXPOSE 9300

USER ctfuser

# gunicorn, not Flask's dev server: the Werkzeug dev server is single-threaded
# and not built for untrusted traffic. --worker-tmp-dir /dev/shm is required
# because the container runs with a read-only root filesystem.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:9300", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "30", \
     "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", \
     "app:app"]
