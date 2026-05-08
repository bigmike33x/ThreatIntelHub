import scrapy

class OnionPageItem(scrapy.Item):
    url          = scrapy.Field()
    title        = scrapy.Field()
    status       = scrapy.Field()
    body_preview = scrapy.Field()
    timestamp    = scrapy.Field()
