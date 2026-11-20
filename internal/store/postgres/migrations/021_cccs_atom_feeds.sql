UPDATE data_sources
SET address = 'https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en'
WHERE id = 'cccs-alerts-advisories';

UPDATE data_sources
SET address = 'https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=news_events_guidance&lang=en'
WHERE id = 'cccs-news-events-guidance';
