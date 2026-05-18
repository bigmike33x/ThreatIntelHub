import scrapy

class OnionPageItem(scrapy.Item):
    url          = scrapy.Field()
    title        = scrapy.Field()
    status       = scrapy.Field()
    body_preview = scrapy.Field()
    timestamp    = scrapy.Field()
    file_links   = scrapy.Field()  # JSON list of (url, ext) tuples

class LeakItem(scrapy.Item):
    url            = scrapy.Field()
    title          = scrapy.Field()
    status         = scrapy.Field()
    confidence     = scrapy.Field()   # 0-100 how confident this is real
    full_text      = scrapy.Field()   # up to 2000 chars
    extracted      = scrapy.Field()   # JSON blob of all extracted data
    cves           = scrapy.Field()   # JSON list of CVE IDs
    breach_targets = scrapy.Field()   # JSON list of company names
    record_counts  = scrapy.Field()   # JSON list of record count strings
    exploit_types  = scrapy.Field()   # JSON list of exploit types
    has_emails     = scrapy.Field()   # 1 if email addresses found
    has_hashes     = scrapy.Field()   # 1 if password hashes found
    has_ssn        = scrapy.Field()   # 1 if SSN patterns found
    has_magnet     = scrapy.Field()   # 1 if magnet/torrent link found
    timestamp      = scrapy.Field()
