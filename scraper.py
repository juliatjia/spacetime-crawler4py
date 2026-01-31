import re
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlunparse
from bs4 import BeautifulSoup

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


def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content (the page)
    
    # only process successful pages
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    raw = resp.raw_response
    content = raw.content
    if not content:
        return []

    # only parse HTML-ish responses; skip downloads like PDFs, images, etc.
    ctype = raw.headers.get("Content-Type", "").lower()
    if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
        return []

    # skip extremely large pages by Content-Length if header exists
    cl = raw.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > 5_000_000:  # 5MB
        return []

    links = []

    # Parse HTML
    soup = BeautifulSoup(content, "lxml") 

    # use the final resolved URL from raw_response.url for joining relative links
    base_url = raw.url if raw.url else url

    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue
        href = href.strip()

        # skip non-links
        if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
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
        
        # basic trap keyword checks
        lower_url = url.lower()
        if any(k in lower_url for k in TRAP_KEYWORDS):
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
