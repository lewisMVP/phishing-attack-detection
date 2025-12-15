import pandas as pd
import os
import time
from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService
from bs4 import BeautifulSoup

# --- CONFIGURATION ---
INPUT_FILE = '../../data/processed/benign_urls.csv' # File chứa URL sạch
IMG_DIR = '../../data/raw/images/'
HTML_DIR = '../../data/raw/html/'
TEXT_DIR = '../../data/raw/text/'
TIMEOUT = 15 # Tăng lên 1 chút vì web sạch thường nặng (nhiều quảng cáo/JS)

# Tạo thư mục
os.makedirs(IMG_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(TEXT_DIR, exist_ok=True)

def setup_driver():
    """
    Setup Edge Driver Optimized for Benign Sites (Block Ads/Downloads, Silent)
    """
    options = EdgeOptions()
    options.add_argument("--window-size=1280,720")
    
    # Tắt Log rác
    options.add_argument("--log-level=3") 
    options.add_argument("--silent")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    # Tắt SmartScreen (để tránh lỗi DNS ảo)
    options.add_argument("--disable-features=msSmartScreenProtection")

    # Khiên chắn an toàn (Chặn download tuyệt đối)
    prefs = {
        "download.default_directory": "NUL",
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "safebrowsing.enabled": True,
        "profile.default_content_settings.popups": 0,
        "plugins.always_open_pdf_externally": True,
    }
    options.add_experimental_option("prefs", prefs)

    # Tìm driver thủ công
    current_folder = os.path.dirname(os.path.abspath(__file__))
    driver_path = os.path.join(current_folder, "msedgedriver.exe")
    
    if not os.path.exists(driver_path):
        print("ERROR: msedgedriver.exe not found!")
        exit()

    service = EdgeService(executable_path=driver_path)
    driver = webdriver.Edge(service=service, options=options)
    driver.set_page_load_timeout(TIMEOUT)
    return driver

def process_benign_urls():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: File {INPUT_FILE} not found.")
        return

    df = pd.read_csv(INPUT_FILE)
    df = df.head(5000) # Lấy danh sách
    
    print(f"Total Benign URLs to process: {len(df)}")
    
    driver = setup_driver()
    log_path = '../../data/processed/downloaded_log.csv'
    skipped_count = 0

    for index, row in df.iterrows():
        raw_url = str(row['url']).strip()
        if not raw_url.startswith('http'):
            url = f"http://{raw_url}"
        else:
            url = raw_url

        label = 0 
        file_id = f"{label}_{index}"
        
        # Smart Resume
        if os.path.exists(f"{IMG_DIR}{file_id}.png"):
            skipped_count += 1
            if skipped_count % 100 == 0:
                print(f"Skipping {skipped_count} existing files...")
            continue 
        
        print(f"[{index}] Processing Benign: {url} ...", end=" ")
        
        try:
            if driver is None:
                driver = setup_driver()

            driver.get(url)
            time.sleep(1.5) 
            
            driver.save_screenshot(f"{IMG_DIR}{file_id}.png")
            
            html_content = driver.page_source
            with open(f"{HTML_DIR}{file_id}.html", "w", encoding="utf-8") as f:
                f.write(html_content)
                
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
            # --- SỬA ĐỔI QUAN TRỌNG Ở ĐÂY ---
            # Bất kể lỗi gì (Timeout, Treo, Lỗi mạng...) -> KILL DRIVER NGAY LẬP TỨC
            print(f"FAILED (Web bị treo hoặc chặn). RESTARTING DRIVER...")
            try:
                driver.quit() # Giết trình duyệt cũ (đang bị kẹt ở eBay)
            except:
                pass
            
            # Khởi tạo lại trình duyệt mới tinh cho URL tiếp theo
            driver = setup_driver()
            # -------------------------------
            continue

    try:
        driver.quit()
    except:
        pass
    print("Benign collection completed!")

if __name__ == "__main__":
    process_benign_urls()