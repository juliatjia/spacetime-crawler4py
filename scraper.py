import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlunparse
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
from tokenizer import tokenize_text_stream
import atexit
import hashlib


NON_STOPWORD_MIN = 300

# --- Near-duplicate detection (SimHash-ish) ---
SIMHASH_BITS = 64
HAMMING_THRESHOLD = 3   
BANDS = 4               # 4 bands => 16-bit chunks
MAX_BUCKET = 2000   # cap per band bucket to avoid memory blow-up

simhash_buckets = defaultdict(list)  # band_key -> list of simhash ints
seen_simhashes = set()               # exact simhash hits

low_info_output = open("low_info.txt", "a")          #prints what files were low info skipped
visited_domains_output = open("visited_domains.txt", "a")


word_counts = Counter()
longest_page = ("", 0)
unique_urls = set()
subdomain_counts = defaultdict(int)
processed_urls = set()


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
    "_files",
    "/events/list",
    "/all-events",
    "image",
    "ical",
    "outlook-ical",
    "share",
    "tab_details",
    "tab_files",
    "do",
    "ns",
    "tribe_events",
    "eventDisplay",
    "tribe-bar-date",
    "project-meeting",
    "info-session",
    "workshop"
)

BAD_QUERY_KEYS = {
    "c", "o",          # Apache directory listing sort options (?C=D;O=A etc.)
    "ical",            # calendar export (?ical=1)
    "session", "sid", "phpsessid", "jsessionid",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid",
    "sort", "order", "orderby", "filter", "view", "format", "eventDate", "paged", "post_type", "idx" # common "variation" params
}

def normalize_url(u: str) -> str:
    p = urlparse(u)
    # lowercase scheme+host
    scheme = (p.scheme or "").lower()
    netloc = (p.netloc or "").lower()
    # collapse // in path
    path = re.sub(r"/{2,}", "/", p.path)
    # strip default port
    netloc = netloc.replace(":80", "").replace(":443", "")
    return urlunparse((scheme, netloc, path, p.params, p.query, ""))  # fragment removed

def _hash64(token: str) -> int:
    # Stable 64-bit hash from token
    h = hashlib.md5(token.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(h[:8], byteorder="big", signed=False)

def simhash64(tokens: list[str]) -> int:
    # tokens should already be "good tokens" (filtered)
    # Weighted SimHash: each token votes on each bit
    v = [0] * SIMHASH_BITS
    for t in tokens:
        x = _hash64(t)
        for i in range(SIMHASH_BITS):
            bit = (x >> i) & 1
            v[i] += 1 if bit else -1

    sig = 0
    for i in range(SIMHASH_BITS):
        if v[i] > 0:
            sig |= (1 << i)
    return sig

def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()

def _band_keys(sig: int) -> list[tuple[int, int]]:
    # Returns keys like (band_index, band_value)
    band_size = SIMHASH_BITS // BANDS  # 16 if 64/4
    keys = []
    mask = (1 << band_size) - 1
    for bi in range(BANDS):
        shift = bi * band_size
        band_val = (sig >> shift) & mask
        keys.append((bi, band_val))
    return keys

def is_near_duplicate(sig: int) -> bool:
    # exact match quick check
    if sig in seen_simhashes:
        return True

    # check candidates in same bands
    candidates = []
    for key in _band_keys(sig):
        candidates.extend(simhash_buckets.get(key, []))

    # if any candidate within threshold, treat as near-duplicate
    for other in candidates:
        if hamming(sig, other) <= HAMMING_THRESHOLD:
            return True

    return False

def add_simhash(sig: int) -> None:
    seen_simhashes.add(sig)
    for key in _band_keys(sig):
        bucket = simhash_buckets[key]
        bucket.append(sig)
        if len(bucket) > MAX_BUCKET:
            # keep only the newest MAX_BUCKET entries
            del bucket[: len(bucket) - MAX_BUCKET]



def scraper(url, resp):
    # links = extract_next_links(url, resp)
    # return [link for link in links if is_valid(link)]

    links = extract_next_links(url, resp)

    out = [] # final list of valid links
    seen = set() # to avoid duplicates
    for link in links:
        # Remove fragment 
        abs_url, _ = urldefrag(link)

        abs_url = normalize_url(abs_url) # normalize
        if abs_url not in seen and abs_url not in processed_urls and is_valid(abs_url):
            seen.add(abs_url)
            out.append(abs_url)

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

    # 2. Defragment + normalize URL for consistent uniqueness
    final_url = raw.url if raw and getattr(raw, "url", None) else url
    crawl_key = normalize_url(urldefrag(final_url)[0])
    report_key = urldefrag(final_url)[0]

    clean_url, _ = urldefrag(final_url)
    clean_url = normalize_url(clean_url)

    if crawl_key in processed_urls:
        return []
    
    # if it's not even a valid target for our crawl, stop (DON'T mark processed)
    if not is_valid(crawl_key):
        return []
    
    processed_urls.add(crawl_key)
    
    soup = BeautifulSoup(content, "lxml")

    if report_key not in unique_urls:
        # Track subdomains (Q4)
        hostname = urlparse(report_key).hostname

        # Text Analytics (Q2 & Q3)
        text = soup.get_text(separator=" ")

        tokens = list(tokenize_text_stream(text))

        # All alphabetic tokens (like old `words`)
        alpha_tokens = [t for t in tokens if t.isalpha()]

        # Non-stopword meaningful tokens
        filtered = [t for t in alpha_tokens if t not in STOPWORDS and len(t) > 1]

        # Low-information checks
        low_non_stop_words = len(filtered) < NON_STOPWORD_MIN

        uniqueness_ratio = (
            len(set(filtered)) / len(filtered)
            if len(filtered) > 0 else 0
        )
        not_unique = uniqueness_ratio < 0.1

        # Text ratio: alphabetic tokens vs all tokens
        text_ratio = (
            len(alpha_tokens) / len(tokens)
            if len(tokens) > 0 else 0
        )
        low_text_ratio = text_ratio < 0.3


        is_low_info = low_non_stop_words or not_unique or low_text_ratio
        if is_low_info:
            print(f"SKIPPED (Low Info): {report_key}", file=low_info_output)
            low_info_output.flush()
            return []       #fix so we dont fall and keep searching traps
        else:
            # near-duplicate detection 
            sig = simhash64(filtered) 
            if is_near_duplicate(sig): 
                print(f"SKIPPED (Near-Duplicate): {report_key}", file=low_info_output)
                low_info_output.flush()
                return []
            unique_urls.add(report_key)
            if hostname and hostname.endswith(".uci.edu"):
                subdomain_counts[hostname.lower()] += 1

            add_simhash(sig)
            word_counts.update(filtered)
        
            global longest_page
            if len(filtered) > longest_page[1]:
                longest_page = (report_key, len(filtered))

    # 3. Link Extraction
    links = []
    base_url = normalize_url(final_url)

    for a in soup.find_all("a", href=True):
        href = a.get("href").strip()
        if href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        
        abs_url = urljoin(base_url, href)
        abs_url, _ = urldefrag(abs_url)
        abs_url = normalize_url(abs_url)
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
        path = parsed.path.lower()

        if "/events" in path or "/event" in path:
            print(f"REJECTED (Events Path): {url}", file=visited_domains_output)
            return False
        
        if parsed.scheme not in set(["http", "https"]):
            print(f"INVALID (Scheme): {url}", file=visited_domains_output)
            return False
        
        # Domain restriction
        host = (parsed.hostname or "").lower()
        if not any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS):
            print(f"REJECTED (Outside Domain): {url}", file=visited_domains_output)
            return False

        
            
        
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz"
            # Added your new extensions here
            + r"|h|cpp|c|java|py|sh|bat|src|db)$", 
            parsed.path.lower()
        ):
            print(f"REJECTED (Static File): {url}", file=visited_domains_output)
            return False

        if re.search(r'/day/\d{4}-\d{2}-\d{2}', path):      #bunch of calendar traps
            print(f"REJECTED (Calendar Day): {url}", file=visited_domains_output)
            return False
        if re.search(r'/day/\d{4}-\d{2}', path):
            print(f"REJECTED (Calendar Day): {url}", file=visited_domains_output)
            return False
        if re.search(r"/\d{4}-\d{2}/", parsed.path) or "ical" in parsed.query.lower():
            with open("visited_domains.txt", "a") as f:
                f.write(f"REJECTED (Archive/Calendar): {url}\n")
            return False
        if re.search(r'/events/\d{4}-\d{2}-\d{2}', path):
            print(f"REJECTED (Calendar Day): {url}", file=visited_domains_output)
            return False
        if re.search(r'/events/tag/.*/day/\d{4}-\d{2}-\d{2}', path):
            print(f"REJECTED (Calendar Day): {url}", file=visited_domains_output)
            return False
        if "outlook-ical" in url.lower() or "/day/" in path:
            print(f"REJECTED (Calendar Day): {url}", file=visited_domains_output)
            return False
        if "gitlab.ics.uci.edu" in parsed.hostname:     #traps for gitlab trees and commits
            return False
        if "~eppstein/pix" in path or "~eppstein/junkyard" in path:     #humongous photo gallery, low info
            return False

        path_segments = [s for s in path.split('/') if s]
        if len(path_segments) != len(set(path_segments)):
            return False

        # NEW: Catch PowerPoint/Web-Export sub-files
        # We saw these in your logs (e.g., /Ch3_files/slide0006.htm)
        if "_files/" in path or "slide" in path:
            print(f"REJECTED (Office Export): {url}", file=visited_domains_output)
            return False
        
        path_segments = [s for s in parsed.path.split('/') if s]
        if len(path_segments) != len(set(path_segments)) or len(path_segments) > 10:
            print(f"REJECTED (Repeating Path or Path Too Deep): {url}", file=visited_domains_output)
            return False


        # added the len url > 200, trap detection for query / length
        # basic trap keyword checks
        lower_url = url.lower()
        if any(k in lower_url for k in TRAP_KEYWORDS) or len(url) > 200:
            print(f"REJECTED (Trap Keyword or Length > 200): {url}", file=visited_domains_output)
            return False


        qs = parse_qs(parsed.query.replace(";", "&"))
        if any(k.lower() in BAD_QUERY_KEYS for k in qs):
            print(f"REJECTED (Bad Query): {url}", file=visited_domains_output)
            return False

        # query-string sanity checks to avoid infinite spaces
        if parsed.query:
            # overly long queries are often traps
            if len(parsed.query) > 200:
                print(f"REJECTED (Query Too Long): {url}", file=visited_domains_output)
                return False

            qs = parse_qs(parsed.query.replace(";", "&"), keep_blank_values=True)

            # too many parameters means likely trap???
            if len(qs) > 8:
                print(f"REJECTED (Too Many Params): {url}", file=visited_domains_output)
                return False

            # avoid excessive paging
            if "page" in qs:
                for v in qs["page"]:
                    if v.isdigit() and int(v) > 500:
                        print(f"REJECTED (Excessive Paging): {url}", file=visited_domains_output)
                        return False

        # super long URLs are often traps
        if len(url) > 300:
            return False
        
        if has_bad_query(url):
            return False
        print(f"VALID: {url}", file=visited_domains_output)
        visited_domains_output.flush() # Ensure it writes immediately
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

atexit.register(print_report)