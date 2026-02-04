import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlunparse
from bs4 import BeautifulSoup
from collections import Counter, defaultdict

word_counts = Counter()
longest_page = ("", 0)
unique_urls = set()
subdomain_counts = defaultdict(int)


ALLOWED_DOMAINS = (
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
)
# common trap-ish words to start with? can add more after testing crawls
TRAP_KEYWORDS = (
    "calendar",
    "wp-json",
    "replytocom",
    "share=",
    "print=",
    "login",
)

BAD_QUERY_KEYS = {
    "c", "o",          # Apache directory listing sort options (?C=D;O=A etc.)
    "ical",            # calendar export (?ical=1)
    "session", "sid", "phpsessid", "jsessionid",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid",
    "sort", "order", "orderby", "filter", "view", "format",  # common "variation" params
}

def scraper(url, resp):
    # links = extract_next_links(url, resp)
    # return [link for link in links if is_valid(link)]

    links = extract_next_links(url, resp)

    out = [] # final list of valid links
    seen = set() # to avoid duplicates
    for link in links:
        # Remove fragment 
        clean, _ = urldefrag(link)
        if clean not in seen and is_valid(clean):
            seen.add(clean)
            out.append(clean)

    return out

try:
    with open("stopwords.txt") as f:
        STOPWORDS = set(w.strip().lower() for w in f)
except FileNotFoundError:
    print("Warning: stopwords.txt not found!")
    STOPWORDS = set()

def extract_next_links(url, resp):
    # 1. Validation: Only process successful HTML pages
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    raw = resp.raw_response
    content = raw.content
    if not content:
        return []

    ctype = raw.headers.get("Content-Type", "").lower()
    if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
        return []

    # 2. Defragment and check uniqueness
    clean_url, _ = urldefrag(url)
    
    # We need soup for both analytics AND link extraction
    soup = BeautifulSoup(content, "lxml")

    if clean_url not in unique_urls:
        unique_urls.add(clean_url)
        
        # Track subdomains (Q4)
        hostname = urlparse(clean_url).hostname
        if hostname and hostname.endswith(".uci.edu"):
            subdomain_counts[hostname.lower()] += 1

        # Text Analytics (Q2 & Q3)
        text = soup.get_text(separator=" ")
        words = re.findall(r"[a-zA-Z]+", text.lower())
        filtered = [w for w in words if w not in STOPWORDS and len(w) > 1]
        
        word_counts.update(filtered)
        
        global longest_page
        if len(filtered) > longest_page[1]:
            longest_page = (clean_url, len(filtered))

    # 3. Link Extraction
    links = []
    base_url = raw.url if raw.url else url

    for a in soup.find_all("a", href=True):
        href = a.get("href").strip()
        if href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        
        abs_url = urljoin(base_url, href)
        links.append(abs_url)

    return links


# helper function to check for bad query keys
def has_bad_query(url: str) -> bool:
    parsed = urlparse(url)

    # Some sites use ; as a query separator too. parse_qs handles &,
    # but not always ; in every environment, so normalize a bit:
    query = parsed.query.replace(";", "&")

    if not query:
        return False

    qs = parse_qs(query, keep_blank_values=True)

    # If ANY bad key appears, reject
    for k in qs.keys():
        if k.lower() in BAD_QUERY_KEYS:
            return True

    # Special-case: sometimes you literally see "C=" or "O=" in raw query
    # even if parse_qs didn't catch it cleanly.
    raw = parsed.query.lower()
    if "c=" in raw or "o=" in raw:
        return True

    return False

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # Domain restriction
        host = (parsed.hostname or "").lower()
        if not any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS):
            return False
        
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", 
            parsed.path.lower()
        ):
            return False
        
        path_segments = [s for s in parsed.path.split('/') if s]
        if len(path_segments) != len(set(path_segments)) or len(path_segments) > 10:
            return False


        # added the len url > 200, trap detection for query / length
        # basic trap keyword checks
        lower_url = url.lower()
        if any(k in lower_url for k in TRAP_KEYWORDS) or len(url) > 200:
            return False


        qs = parse_qs(parsed.query.replace(";", "&"))
        if any(k.lower() in BAD_QUERY_KEYS for k in qs):
            return False



        # query-string sanity checks to avoid infinite spaces
        if parsed.query:
            # overly long queries are often traps
            if len(parsed.query) > 200:
                return False

            qs = parse_qs(parsed.query.replace(";", "&"), keep_blank_values=True)

            # too many parameters means likely trap???
            if len(qs) > 8:
                return False

            # avoid excessive paging
            if "page" in qs:
                for v in qs["page"]:
                    if v.isdigit() and int(v) > 500:
                        return False

        # super long URLs are often traps
        if len(url) > 300:
            return False
        
        if has_bad_query(url):
            return False

        return True


    except TypeError:
        print ("TypeError for ", parsed)
        raise

    except Exception:
        return False


def print_report():
    print("\n" + "="*30)
    print("CRAWLER REPORT SUMMARY")
    print("="*30)
    
    # Q1: Unique Pages
    print(f"1. Unique pages found: {len(unique_urls)}")
    
    # Q2: Longest Page
    print(f"2. Longest page: {longest_page[0]} ({longest_page[1]} words)")
    
    # Q3: 50 Most Common Words
    print("3. Top 50 words:")
    for word, count in word_counts.most_common(50):
        print(f"   {word}: {count}")
        
    # Q4: Subdomains
    print("4. Subdomains found:")
    for sub, count in sorted(subdomain_counts.items()):
        print(f"   {sub}, {count}")
    print("="*30 + "\n")