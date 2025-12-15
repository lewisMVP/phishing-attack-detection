import pandas as pd
import os
import time
import json
from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService
from bs4 import BeautifulSoup

# --- CONFIGURATION ---
INPUT_FILE = '../../data/processed/phishing_urls.csv' # Change to benign_urls.csv for benign dataset
IMG_DIR = '../../data/raw/images/'
HTML_DIR = '../../data/raw/html/'
TEXT_DIR = '../../data/raw/text/'
TIMEOUT = 10 # Seconds

# Create directories if they don't exist
os.makedirs(IMG_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(TEXT_DIR, exist_ok=True)

def setup_driver():
    """
    Setup Edge Driver with MAX SECURITY mode (Block Downloads).
    """
    options = EdgeOptions()
    options.add_argument("--window-size=1280,720")
    options.add_argument("--disable-notifications")
    options.add_argument("--ignore-certificate-errors")
    
    # --- SAFETY SHIELD (BLOCK DOWNLOADS) ---
    prefs = {
        # 1. Redirect downloads to NUL (Blackhole on Windows)
        "download.default_directory": "NUL", 
        
        # 2. Suppress download prompts
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        
        # 3. Enable Safe Browsing but strictly block malicious content
        "safebrowsing.enabled": True,
        
        # 4. Block Pop-ups
        "profile.default_content_settings.popups": 0,
        
        # 5. Force open PDFs externally (prevent in-browser execution)
        "plugins.always_open_pdf_externally": True,
    }
    options.add_experimental_option("prefs", prefs)
    # ---------------------------------------

    # Locate the manual msedgedriver.exe in the same directory
    current_folder = os.path.dirname(os.path.abspath(__file__))
    driver_path = os.path.join(current_folder, "msedgedriver.exe")
    
    if not os.path.exists(driver_path):
        print(f"ERROR: Driver not found at {driver_path}")
        print("Please download msedgedriver.exe and place it in this folder.")
        exit()

    service = EdgeService(executable_path=driver_path)
    driver = webdriver.Edge(service=service, options=options)
    driver.set_page_load_timeout(TIMEOUT)
    return driver

def process_urls():
    df = pd.read_csv(INPUT_FILE)
    print(f"Total URLs in list: {len(df)}")
    
    # Khởi tạo trình duyệt lần đầu
    driver = setup_driver()
    
    log_path = '../../data/processed/downloaded_log.csv'
    skipped_count = 0

    for index, row in df.iterrows():
        url = row['url']
        label = row.get('label', 1) 
        file_id = f"{label}_{index}"
        
        # --- SMART RESUME ---
        if os.path.exists(f"{IMG_DIR}{file_id}.png"):
            skipped_count += 1
            if skipped_count % 1000 == 0:
                print(f"Skipping {skipped_count} URLs already downloaded...")
            continue 
        # --------------------
        
        print(f"[{index}] Processing: {url} ...", end=" ")
        
        try:
            # Kiểm tra xem driver có còn sống không trước khi gọi lệnh
            if driver is None:
                driver = setup_driver()

            driver.get(url)
            time.sleep(2) 
            
            # 1. Save Screenshot
            driver.save_screenshot(f"{IMG_DIR}{file_id}.png")
            
            # 2. Save HTML
            html_content = driver.page_source
            with open(f"{HTML_DIR}{file_id}.html", "w", encoding="utf-8") as f:
                f.write(html_content)
                
            # 3. Save Text
            soup = BeautifulSoup(html_content, 'html.parser')
            for script in soup(["script", "style"]):
                script.extract()
            text_content = soup.get_text(separator=' ')
            with open(f"{TEXT_DIR}{file_id}.txt", "w", encoding="utf-8") as f:
                f.write(text_content.strip())
            
            print("OK")
            
            log_entry = pd.DataFrame([{'url': url, 'label': label, 'file_id': file_id}])
            write_header = not os.path.exists(log_path)
            log_entry.to_csv(log_path, mode='a', header=write_header, index=False)
            
        except Exception as e:
            err_msg = str(e)
            print(f"FAILED.")
            
            # --- CƠ CHẾ HỒI SINH (AUTO-RESTART) ---
            # Nếu gặp lỗi session id (trình duyệt chết), ta khởi động lại ngay
            if "invalid session id" in err_msg or "no such window" in err_msg or "chrome not reachable" in err_msg:
                print(f"!!! BROWSER CRASHED ({err_msg[:50]}...). RESTARTING DRIVER...")
                try:
                    driver.quit() # Cố gắng tắt cái cũ đi cho sạch
                except:
                    pass
                
                # Khởi tạo lại driver mới cứng
                driver = setup_driver()
                print(">>> New driver initialized. Resuming...")
            # --------------------------------------
            
            continue

    # Kết thúc vòng lặp
    try:
        driver.quit()
    except:
        pass
    print("Process completed successfully!")

if __name__ == "__main__":
    process_urls()