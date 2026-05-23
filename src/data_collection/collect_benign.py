"""
Benign URL Collection - Multi-Source Aggregator (v3)
=====================================================
Collects diverse, realistic benign URLs from multiple sources:
  1. Tranco Root — Top domains with varied schemes/prefixes
  2. Tranco + Paths — Domains with common subpages
  3. Tranco + Subdomains — Domains with realistic subdomains + paths
  4. Common Crawl CDX API — Real crawled URLs (optional, network-dependent)
  5. Wayback Machine CDX API — Archived URLs (optional, network-dependent)
  6. Curated seed list — Hand-picked complex but safe URLs

Design principle:
  - Sources 1-3 + 6 are fully offline (only need Tranco download) and
    GUARANTEE at least 15,000 URLs even if all APIs fail.
  - Sources 4-5 are online bonuses that add real-world diversity.

Target: ~18,000 unique benign URLs with diverse structure.
"""
import pandas as pd
import requests
import zipfile
import io
import os
import time
import json
import random
from datetime import datetime


# --- CONFIGURATION ---
# Keep class balance with phishing dataset (15,000)
TARGET_URLS = 15000

# Tranco-based generation (offline, always works)
TRANCO_ROOT_COUNT = 5000
TRANCO_PATHS_COUNT = 7000
TRANCO_SUBDOMAIN_COUNT = 5000

# Online sources (bonus, may fail — script works without them)
CC_TARGET = 3000
CC_URLS_PER_DOMAIN = 8
CC_DOMAINS_TO_QUERY = 600
CC_REQUEST_TIMEOUT = 8
CC_DELAY = 0.8
CC_MAX_ERRORS = 5

WAYBACK_TARGET = 1500
WAYBACK_DOMAINS_TO_QUERY = 200
WAYBACK_URLS_PER_DOMAIN = 12
WAYBACK_DELAY = 0.6
WAYBACK_MAX_ERRORS = 5

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'processed')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'benign_urls.csv')


# =========================================================================
# CURATED SEED URLs — complex but legitimate URLs the model must learn
# =========================================================================
CURATED_SAFE_URLS = [
    # --- Security & Research ---
    "https://talosintelligence.com/",
    "https://talosintelligence.com/vulnerability_info",
    "https://blog.talosintelligence.com/threat-roundup/",
    "https://www.virustotal.com/gui/home/upload",
    "https://www.shodan.io/dashboard",
    "https://attack.mitre.org/techniques/enterprise/",
    "https://nvd.nist.gov/vuln/search",
    "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=xss",
    "https://www.exploit-db.com/exploits/51234",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://securelist.com/category/apt-reports/",
    "https://www.abuseipdb.com/check/8.8.8.8",
    "https://urlscan.io/result/some-scan-id/",
    "https://any.run/report/abc123def456",
    "https://bazaar.abuse.ch/browse/",
    "https://www.hybrid-analysis.com/sample/abc123",
    "https://otx.alienvault.com/pulse/abc123",
    "https://www.malwarebytes.com/blog/news",
    "https://www.sentinelone.com/labs/",
    "https://research.checkpoint.com/",
    # --- Google Services ---
    "https://www.google.com/search?q=python+tutorial",
    "https://www.google.com/maps/place/Hanoi",
    "https://www.google.com/intl/en/about/products/",
    "https://docs.google.com/document/d/1abc123xyz/edit",
    "https://docs.google.com/spreadsheets/d/1xyz/edit#gid=0",
    "https://drive.google.com/file/d/1234567890/view",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://accounts.google.com/signin/v2/identifier",
    "https://calendar.google.com/calendar/u/0/r",
    "https://meet.google.com/abc-defg-hij",
    "https://cloud.google.com/products/compute",
    "https://console.cloud.google.com/home/dashboard",
    "https://play.google.com/store/apps/details?id=com.whatsapp",
    "https://translate.google.com/?sl=en&tl=vi",
    "https://colab.research.google.com/drive/1xyz",
    "https://scholar.google.com/scholar?q=machine+learning",
    "https://fonts.google.com/specimen/Roboto",
    "https://news.google.com/topstories?hl=en-US",
    "https://photos.google.com/album/abc123",
    "https://myaccount.google.com/security",
    # --- Microsoft Services ---
    "https://portal.azure.com/#home",
    "https://outlook.live.com/mail/0/inbox",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://teams.microsoft.com/_#/conversations",
    "https://learn.microsoft.com/en-us/dotnet/csharp/",
    "https://dev.azure.com/organization/project/_git/repo",
    "https://visualstudio.microsoft.com/downloads/",
    "https://www.office.com/launch/word",
    "https://onedrive.live.com/?id=root&cid=ABC123",
    "https://support.microsoft.com/en-us/windows",
    "https://www.microsoft.com/en-us/microsoft-365",
    "https://copilot.microsoft.com/",
    # --- Amazon / AWS ---
    "https://www.amazon.com/dp/B09G9FPHY6/ref=cm_sw_r",
    "https://www.amazon.com/gp/bestsellers/",
    "https://aws.amazon.com/console/",
    "https://console.aws.amazon.com/ec2/v2/home?region=us-east-1",
    "https://s3.console.aws.amazon.com/s3/buckets/my-bucket",
    "https://docs.aws.amazon.com/lambda/latest/dg/welcome.html",
    "https://aws.amazon.com/blogs/aws/",
    # --- Social Media ---
    "https://www.facebook.com/profile.php?id=100000123456",
    "https://www.facebook.com/marketplace/",
    "https://www.instagram.com/accounts/login/",
    "https://www.instagram.com/explore/tags/photography/",
    "https://twitter.com/i/flow/login",
    "https://x.com/home",
    "https://www.linkedin.com/in/username/",
    "https://www.linkedin.com/jobs/search/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLxyz",
    "https://studio.youtube.com/channel/UCxyz/videos",
    "https://www.tiktok.com/@username/video/1234567890",
    "https://www.reddit.com/r/programming/comments/abc123/title/",
    "https://old.reddit.com/r/netsec/",
    "https://discord.com/channels/123456789/987654321",
    "https://www.pinterest.com/pin/123456789/",
    "https://www.twitch.tv/directory/game/Just%20Chatting",
    "https://www.snapchat.com/add/username",
    "https://www.threads.net/@username",
    # --- Developer & Tech ---
    "https://github.com/microsoft/vscode/blob/main/README.md",
    "https://github.com/torvalds/linux/tree/master/kernel",
    "https://github.com/features/copilot",
    "https://gist.github.com/user/abc123",
    "https://stackoverflow.com/questions/12345678/how-to-fix-error",
    "https://stackoverflow.com/tags/python/info",
    "https://gitlab.com/user/repo/-/merge_requests/1",
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/tensorflow/",
    "https://hub.docker.com/_/python",
    "https://registry.npmjs.org/express",
    "https://vercel.com/dashboard",
    "https://app.netlify.com/sites/mysite/overview",
    "https://docs.python.org/3/library/urllib.html",
    "https://docs.python.org/3/tutorial/index.html",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://developer.mozilla.org/en-US/docs/Web/CSS/Flexbox",
    "https://reactjs.org/docs/getting-started.html",
    "https://vuejs.org/guide/introduction.html",
    "https://angular.io/tutorial/first-app",
    "https://nextjs.org/docs/getting-started",
    "https://kubernetes.io/docs/concepts/overview/",
    "https://www.terraform.io/docs/providers/aws/",
    "https://grafana.com/docs/grafana/latest/",
    "https://prometheus.io/docs/prometheus/latest/querying/basics/",
    "https://www.jetbrains.com/idea/download/",
    "https://code.visualstudio.com/docs",
    "https://www.postman.com/downloads/",
    "https://www.figma.com/file/abc123/Design-System",
    "https://www.canva.com/design/DAFxyz/edit",
    # --- News & Media ---
    "https://www.bbc.com/news/world-asia-12345678",
    "https://www.bbc.com/sport/football",
    "https://edition.cnn.com/2024/01/15/tech/ai-news/index.html",
    "https://www.reuters.com/technology/artificial-intelligence/",
    "https://www.nytimes.com/2024/01/15/technology/ai-chatbots.html",
    "https://www.theguardian.com/technology/2024/jan/15/article-title",
    "https://techcrunch.com/2024/01/15/startup-funding/",
    "https://arstechnica.com/science/2024/01/article-title/",
    "https://www.wired.com/story/article-title/",
    "https://www.theverge.com/2024/1/15/article",
    "https://www.washingtonpost.com/technology/2024/01/15/article/",
    "https://apnews.com/article/abc123",
    "https://www.aljazeera.com/news/2024/1/15/article",
    # --- Vietnamese trusted sites ---
    "https://vnexpress.net/the-gioi/tin-tuc-4567890.html",
    "https://vnexpress.net/kinh-doanh",
    "https://tuoitre.vn/tin-moi-nhat-20240115.htm",
    "https://thanhnien.vn/cong-nghe/bai-viet-123456.html",
    "https://dantri.com.vn/suc-khoe/bai-viet-20240115.htm",
    "https://vietnamnet.vn/en/",
    "https://shopee.vn/product/123456789/987654321",
    "https://tiki.vn/san-pham/laptop-abc-p12345678.html",
    "https://momo.vn/nap-tien-dien-thoai",
    "https://www.vietcombank.com.vn/en/Personal",
    "https://www.techcombank.com.vn/khach-hang-ca-nhan",
    "https://fptshop.com.vn/dien-thoai",
    "https://cellphones.com.vn/laptop.html",
    "https://www.dienmayxanh.com/may-giat",
    "https://batdongsan.com.vn/ban-can-ho-chung-cu",
    # --- Finance (legitimate) ---
    "https://www.paypal.com/myaccount/summary",
    "https://www.paypal.com/us/digital-wallet/send-receive-money",
    "https://www.chase.com/personal/checking",
    "https://www.bankofamerica.com/online-banking/sign-in/",
    "https://finance.yahoo.com/quote/AAPL/",
    "https://finance.yahoo.com/markets/",
    "https://www.coinbase.com/price/bitcoin",
    "https://www.bloomberg.com/markets/stocks",
    "https://www.investing.com/currencies/eur-usd",
    "https://www.tradingview.com/chart/",
    # --- E-commerce & SaaS ---
    "https://www.ebay.com/itm/123456789012",
    "https://www.ebay.com/b/Electronics/bn_7000259124",
    "https://www.etsy.com/listing/1234567890/handmade-item",
    "https://www.shopify.com/admin/products",
    "https://www.notion.so/workspace/Getting-Started-abc123",
    "https://trello.com/b/abc123/board-name",
    "https://slack.com/intl/en-vn/",
    "https://zoom.us/j/1234567890?pwd=xyzABC",
    "https://www.dropbox.com/home/Documents",
    "https://www.salesforce.com/products/",
    "https://www.hubspot.com/products/crm",
    "https://www.atlassian.com/software/jira",
    "https://www.zendesk.com/support/",
    "https://www.mailchimp.com/email-marketing/",
    # --- Education & Reference ---
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Cybersecurity",
    "https://www.khanacademy.org/computing/computer-science",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python-bootcamp/",
    "https://www.edx.org/learn/computer-science",
    "https://arxiv.org/abs/2301.12345",
    "https://www.researchgate.net/publication/12345678",
    "https://www.wolframalpha.com/input?i=integrate+x%5E2",
    "https://www.britannica.com/science/artificial-intelligence",
    "https://www.mit.edu/research/",
    "https://www.stanford.edu/academics/",
    "https://www.harvard.edu/programs/",
    # --- Government & Institutions ---
    "https://www.irs.gov/refunds",
    "https://www.usa.gov/government-benefits",
    "https://www.who.int/news-room/fact-sheets/detail/covid-19",
    "https://data.gov/dataset/",
    "https://www.un.org/en/about-us/",
    "https://ec.europa.eu/info/strategy/priorities-2019-2024_en",
    "https://www.nasa.gov/missions/",
    "https://www.nih.gov/health-information",
    "https://www.fda.gov/drugs",
    "https://www.sec.gov/cgi-bin/browse-edgar",
    # --- Misc popular ---
    "https://www.weather.com/weather/today/",
    "https://www.imdb.com/title/tt0111161/",
    "https://www.rottentomatoes.com/m/the_shawshank_redemption",
    "https://www.goodreads.com/book/show/1885.Pride_and_Prejudice",
    "https://www.tripadvisor.com/Hotels",
    "https://www.booking.com/searchresults.html?dest_id=-1",
    "https://www.airbnb.com/s/homes",
    "https://www.craigslist.org/about/sites",
    "https://www.yelp.com/search?find_desc=restaurants",
    "https://www.zillow.com/homes/for_sale/",
    "https://www.healthline.com/health/anxiety",
    "https://www.webmd.com/a-to-z-guides/",
    "https://www.mayoclinic.org/diseases-conditions",
    "https://www.speedtest.net/",
    "https://www.archive.org/details/texts",
]


# Subpages appended to Tranco domains
_COMMON_PATHS = [
    "/", "/about", "/about-us", "/contact", "/contact-us",
    "/login", "/signup", "/register", "/pricing", "/plans",
    "/blog", "/blog/latest", "/help", "/help/faq", "/support",
    "/terms", "/terms-of-service", "/privacy", "/privacy-policy",
    "/products", "/services", "/solutions", "/features",
    "/careers", "/jobs", "/news", "/press", "/faq",
    "/docs", "/documentation", "/api", "/api/v1", "/developers",
    "/dashboard", "/settings", "/account", "/profile",
    "/search?q=test", "/search?q=hello+world&page=1",
    "/en/", "/vi/", "/fr/", "/de/", "/ja/",
    "/sitemap.xml", "/robots.txt", "/feed", "/rss",
    "/category/technology", "/category/news", "/category/business",
    "/2024/01/article-title", "/2024/02/news-update",
    "/user/profile", "/user/settings",
    "/download", "/downloads", "/resources", "/tools",
    "/community", "/forum", "/discussions",
    "/status", "/changelog", "/releases",
    "/images/logo.png", "/assets/style.css",
]

# Common subdomains for generating realistic URLs
_COMMON_SUBDOMAINS = [
    "www", "mail", "blog", "docs", "app", "api", "m",
    "cdn", "static", "media", "images", "support", "help",
    "shop", "store", "portal", "my", "account", "admin",
    "dev", "staging", "status", "news", "forum", "community",
    "cloud", "dashboard", "secure", "auth", "login",
]


def download_tranco_list():
    """
    Download Tranco Top 1M and produce three sets:
      1. Root domains (varied scheme + www prefix)
      2. Domains + common paths
      3. Domains + subdomains + paths
    Returns (root_df, paths_df, subdomain_df, raw_domains)
    """
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print("\n" + "=" * 60)
    print("[Tranco] Downloading Top 1M list...")
    print("=" * 60)

    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(response.content))

        with z.open('top-1m.csv') as f:
            data = pd.read_csv(f, header=None, names=['rank', 'domain'])

        all_domains = data['domain'].tolist()

        # --- Set 1: Root domains (varied scheme + www) ---
        root_domains = all_domains[:TRANCO_ROOT_COUNT]
        root_urls = []
        for d in root_domains:
            scheme = random.choice(["https://"] * 3 + ["http://"])
            prefix = random.choice(["", "www."])
            root_urls.append(f"{scheme}{prefix}{d}")

        root_df = pd.DataFrame({'url': root_urls, 'source': 'tranco_root'})

        # --- Set 2: Domains + common paths ---
        path_pool = all_domains[:8000]
        random.shuffle(path_pool)
        path_urls = []
        for d in path_pool:
            if len(path_urls) >= TRANCO_PATHS_COUNT:
                break
            n_paths = random.randint(1, 3)
            chosen = random.sample(_COMMON_PATHS, min(n_paths, len(_COMMON_PATHS)))
            for p in chosen:
                if len(path_urls) >= TRANCO_PATHS_COUNT:
                    break
                scheme = random.choice(["https://"] * 4 + ["http://"])
                prefix = random.choice(["", "www."])
                path_urls.append(f"{scheme}{prefix}{d}{p}")

        paths_df = pd.DataFrame({'url': path_urls, 'source': 'tranco_paths'})

        # --- Set 3: Domains + subdomains + paths ---
        sub_pool = all_domains[:6000]
        random.shuffle(sub_pool)
        sub_urls = []
        for d in sub_pool:
            if len(sub_urls) >= TRANCO_SUBDOMAIN_COUNT:
                break
            n = random.randint(1, 2)
            subs = random.sample(_COMMON_SUBDOMAINS, min(n, len(_COMMON_SUBDOMAINS)))
            for sub in subs:
                if len(sub_urls) >= TRANCO_SUBDOMAIN_COUNT:
                    break
                path = random.choice(_COMMON_PATHS)
                sub_urls.append(f"https://{sub}.{d}{path}")

        subdomain_df = pd.DataFrame({'url': sub_urls, 'source': 'tranco_subdomains'})

        print(f"[Tranco] Root URLs:      {len(root_df)}")
        print(f"[Tranco] With paths:     {len(paths_df)}")
        print(f"[Tranco] With subdomains:{len(subdomain_df)}")
        return root_df, paths_df, subdomain_df, all_domains

    except Exception as e:
        print(f"[Tranco] ERROR: {e}")
        empty = pd.DataFrame(columns=['url', 'source'])
        return empty, empty, empty, []


def collect_from_commoncrawl(domains):
    """
    Query Common Crawl CDX API for real crawled URLs.
    This is a bonus source — the script works fine without it.
    Does a quick connectivity probe first to avoid long waits.
    """
    print("\n" + "=" * 60)
    print("[CommonCrawl] Querying CDX API (bonus source)...")
    print(f"[CommonCrawl] Target: {CC_TARGET} URLs")
    print("=" * 60)

    cdx_apis = [
        "https://index.commoncrawl.org/CC-MAIN-2025-08-index",
        "https://index.commoncrawl.org/CC-MAIN-2024-51-index",
        "https://index.commoncrawl.org/CC-MAIN-2024-42-index",
    ]
    headers = {'User-Agent': 'phishing-research/2.0 (academic)'}

    # Quick connectivity probe with a known domain
    working_api = None
    test_params = {'url': '*.google.com/*', 'output': 'json', 'fl': 'url', 'limit': 1}
    for api in cdx_apis:
        try:
            r = requests.get(api, params=test_params, headers=headers, timeout=CC_REQUEST_TIMEOUT)
            if r.status_code == 200:
                working_api = api
                print(f"[CommonCrawl] Connected to {api.split('/')[-1]}")
                break
        except requests.exceptions.RequestException:
            continue

    if not working_api:
        print("[CommonCrawl] SKIPPED — API unreachable (all indices failed probe).")
        return pd.DataFrame(columns=['url', 'source'])

    top = domains[:200]
    rest = domains[200:min(2000, len(domains))]
    sample_size = min(CC_DOMAINS_TO_QUERY - len(top), len(rest))
    query_domains = top + (random.sample(rest, sample_size) if sample_size > 0 else [])

    all_urls = []
    errors = 0
    processed = 0

    for domain in query_domains:
        if len(all_urls) >= CC_TARGET:
            break
        if errors >= CC_MAX_ERRORS:
            print(f"[CommonCrawl] {errors} consecutive errors. Stopping.")
            break

        try:
            params = {
                'url': f'*.{domain}/*',
                'output': 'json',
                'fl': 'url,status',
                'filter': '=status:200',
                'limit': CC_URLS_PER_DOMAIN,
            }
            resp = requests.get(working_api, params=params, headers=headers,
                                timeout=CC_REQUEST_TIMEOUT)

            if resp.status_code != 200:
                errors += 1
                continue

            domain_urls = []
            for line in resp.text.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    u = entry.get('url', '').strip()
                    if u and u.startswith('http'):
                        domain_urls.append(u)
                except (json.JSONDecodeError, ValueError):
                    continue

            if domain_urls:
                all_urls.extend(list(set(domain_urls))[:CC_URLS_PER_DOMAIN])
                errors = 0

            processed += 1
            if processed % 50 == 0:
                print(f"[CommonCrawl] {processed} domains → {len(all_urls)} URLs")

            time.sleep(CC_DELAY)

        except Exception:
            errors += 1
            time.sleep(CC_DELAY)

    if not all_urls:
        print("[CommonCrawl] No URLs collected.")
        return pd.DataFrame(columns=['url', 'source'])

    df = pd.DataFrame({'url': all_urls, 'source': 'commoncrawl'})
    df = df.drop_duplicates(subset=['url'])
    print(f"[CommonCrawl] Collected {len(df)} URLs from {processed} domains.")
    return df


def collect_from_wayback(domains):
    """
    Query Wayback Machine CDX API for archived URLs.
    This is a bonus source — the script works fine without it.
    Does a quick connectivity probe first.
    """
    print("\n" + "=" * 60)
    print("[Wayback] Querying Wayback Machine (bonus source)...")
    print(f"[Wayback] Target: {WAYBACK_TARGET} URLs")
    print("=" * 60)

    api = "https://web.archive.org/cdx/search/cdx"

    # Quick connectivity probe
    try:
        r = requests.get(api, params={
            'url': 'google.com/*', 'output': 'json', 'fl': 'original', 'limit': 1
        }, timeout=CC_REQUEST_TIMEOUT)
        if r.status_code != 200:
            raise ConnectionError(f"status {r.status_code}")
        print("[Wayback] API reachable.")
    except Exception as e:
        print(f"[Wayback] SKIPPED — API unreachable ({e}).")
        return pd.DataFrame(columns=['url', 'source'])

    pool = domains[:3000]
    random.shuffle(pool)
    query_domains = pool[:WAYBACK_DOMAINS_TO_QUERY]

    all_urls = []
    errors = 0
    processed = 0

    for domain in query_domains:
        if len(all_urls) >= WAYBACK_TARGET:
            break
        if errors >= WAYBACK_MAX_ERRORS:
            print(f"[Wayback] {errors} consecutive errors. Stopping.")
            break

        try:
            resp = requests.get(api, params={
                'url': f'{domain}/*',
                'output': 'json',
                'fl': 'original',
                'filter': 'statuscode:200',
                'limit': WAYBACK_URLS_PER_DOMAIN,
                'collapse': 'urlkey',
            }, timeout=CC_REQUEST_TIMEOUT)

            if resp.status_code != 200:
                errors += 1
                continue

            data = resp.json()
            domain_urls = []
            for row in data[1:]:
                u = row[0] if row else ''
                if u and u.startswith('http'):
                    domain_urls.append(u)

            if domain_urls:
                all_urls.extend(list(set(domain_urls))[:WAYBACK_URLS_PER_DOMAIN])
                errors = 0

            processed += 1
            if processed % 30 == 0:
                print(f"[Wayback] {processed} domains → {len(all_urls)} URLs")

            time.sleep(WAYBACK_DELAY)

        except Exception:
            errors += 1
            time.sleep(WAYBACK_DELAY)

    if not all_urls:
        print("[Wayback] No URLs collected.")
        return pd.DataFrame(columns=['url', 'source'])

    df = pd.DataFrame({'url': all_urls, 'source': 'wayback'})
    df = df.drop_duplicates(subset=['url'])
    print(f"[Wayback] Collected {len(df)} URLs from {processed} domains.")
    return df


def _clean_and_validate(df: pd.DataFrame) -> pd.DataFrame:
    """Remove invalid, duplicate, and suspicious-looking URLs."""
    df = df.copy()
    df['url'] = df['url'].astype(str).str.strip()
    df = df[df['url'].str.len() > 0]
    df = df[df['url'].str.len() <= 500]
    df = df[df['url'].str.match(r'^https?://', na=False)]

    bad_patterns = [r'\.exe$', r'\.zip$', r'\.rar$', r'\.scr$',
                    r'data:text', r'javascript:', r'%00']
    for pat in bad_patterns:
        df = df[~df['url'].str.contains(pat, case=False, na=False, regex=True)]

    df['_norm'] = df['url'].str.lower().str.rstrip('/')
    df = df.drop_duplicates(subset=['_norm'], keep='first')
    df = df.drop(columns=['_norm'])
    return df.reset_index(drop=True)


def collect_all_benign():
    """Collect benign URLs from all sources, merge, deduplicate, and save."""
    print("=" * 60)
    print("  BENIGN URL COLLECTION v3 — MULTI-SOURCE AGGREGATOR")
    print(f"  Target: ~{TARGET_URLS} unique URLs (diverse structure)")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # --- 1. Tranco (guaranteed offline sources) ---
    print("\n[STEP 1/4] Collecting from Tranco List...")
    tranco_root, tranco_paths, tranco_subs, domains = download_tranco_list()

    # --- 2. Online bonus sources ---
    print("\n[STEP 2/4] Collecting from online APIs (bonus)...")
    cc_df = pd.DataFrame(columns=['url', 'source'])
    wb_df = pd.DataFrame(columns=['url', 'source'])

    if domains:
        try:
            cc_df = collect_from_commoncrawl(domains)
        except Exception as e:
            print(f"[CommonCrawl] FAILED: {e}")

        try:
            wb_df = collect_from_wayback(domains)
        except Exception as e:
            print(f"[Wayback] FAILED: {e}")
    else:
        print("  SKIPPED: No Tranco domains available.")

    # --- 3. Curated ---
    print("\n[STEP 3/4] Adding curated seed URLs...")
    curated_df = pd.DataFrame({'url': CURATED_SAFE_URLS, 'source': 'curated'})
    print(f"[Curated] {len(curated_df)} hand-picked URLs added.")

    # --- 4. Merge, clean, save ---
    print("\n[STEP 4/4] Merging, cleaning, and saving...")

    all_dfs = []
    for name, df in [('Tranco Root', tranco_root),
                     ('Tranco+Paths', tranco_paths),
                     ('Tranco+Subdomains', tranco_subs),
                     ('CommonCrawl', cc_df),
                     ('Wayback', wb_df),
                     ('Curated', curated_df)]:
        if not df.empty:
            all_dfs.append(df)
            print(f"  {name}: {len(df)} URLs")
        else:
            print(f"  {name}: 0 URLs")

    if not all_dfs:
        print("\nERROR: No data collected!")
        return

    combined = pd.concat(all_dfs, ignore_index=True)
    raw_total = len(combined)
    combined = _clean_and_validate(combined)
    print(f"\n  Raw: {raw_total} -> After dedup/clean: {len(combined)}")

    if len(combined) > TARGET_URLS:
        print(f"  Trimming to {TARGET_URLS}...")
        final_parts = []
        remaining = TARGET_URLS
        counts = combined['source'].value_counts().sort_values()

        for i, source in enumerate(counts.index):
            src_df = combined[combined['source'] == source]
            left = len(counts) - i
            share = remaining // left
            if len(src_df) <= share:
                final_parts.append(src_df)
                remaining -= len(src_df)
            else:
                final_parts.append(src_df.sample(n=share, random_state=42))
                remaining -= share

        combined = pd.concat(final_parts).sample(frac=1, random_state=42).reset_index(drop=True)

    combined['label'] = 0
    combined['collected_at'] = datetime.now().isoformat()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)

    # --- Report ---
    has_path = combined['url'].str.contains(r'https?://[^/]+/.+', regex=True, na=False).sum()
    has_https = combined['url'].str.startswith('https://').sum()
    has_subdomain = combined['url'].str.match(
        r'https?://\w+\.\w+\.\w+', na=False
    ).sum()
    lengths = combined['url'].str.len()

    print("\n" + "=" * 60)
    print("  COLLECTION COMPLETE!")
    print("=" * 60)
    print(f"  Output: {OUTPUT_FILE}")
    print(f"  Total URLs: {len(combined)}")
    print(f"\n  Source breakdown:")
    for src, cnt in combined['source'].value_counts().items():
        print(f"    - {src}: {cnt} ({cnt/len(combined)*100:.1f}%)")
    print(f"\n  Quality metrics:")
    print(f"    - With paths:      {has_path} ({has_path/len(combined)*100:.1f}%)")
    print(f"    - HTTPS:           {has_https} ({has_https/len(combined)*100:.1f}%)")
    print(f"    - With subdomains: {has_subdomain} ({has_subdomain/len(combined)*100:.1f}%)")
    print(f"    - Avg length:      {lengths.mean():.1f}")
    print(f"    - Median length:   {lengths.median():.1f}")
    print(f"\n  Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    collect_all_benign()
