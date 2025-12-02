FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY analyze_packages.py .

# Set the script as executable
RUN chmod +x analyze_packages.py

# Run the script
CMD ["python", "analyze_packages.py"]

