# Detailed Installation Guide

## Windows Installation

### Prerequisites
- Windows 7 or later
- Python 3.8 or higher
- Administrator privileges for port binding

### Step-by-Step Installation

1. **Download Python**
   - Visit https://www.python.org/downloads/
   - Download Python 3.11 or later
   - During installation, **check "Add Python to PATH"**

2. **Download Speedpot**
   ```bash
   git clone https://github.com/yourusername/speedpot.git
   cd speedpot
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Speedpot**
   ```bash
   python main.py
   ```

### Troubleshooting

#### Python not found
- Ensure Python is added to PATH
- Restart your terminal/command prompt
- Try `python --version` to verify

#### Port binding failed
- Some ports require admin privileges
- Run command prompt as Administrator
- Or select 127.0.0.1 instead of 0.0.0.0

#### Missing dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

## Linux/macOS Installation (Experimental)

1. **Install dependencies**
   ```bash
   sudo apt-get install python3-tk  # Linux only
   ```

2. **Follow Windows installation steps 2-4**

3. **Note**: GUI may have rendering issues on Linux/macOS

## Docker Installation

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 21 22 23 25 80 443 3389 8080
CMD ["python", "main.py"]
```

Build and run:
```bash
docker build -t speedpot .
docker run -p 21:21 -p 22:22 -p 23:23 -p 25:25 -p 80:80 \
           -p 443:443 -p 3389:3389 -p 8080:8080 speedpot
