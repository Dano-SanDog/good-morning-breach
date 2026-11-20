ALTER TABLE data_sources DROP CONSTRAINT IF EXISTS data_sources_format_check;
ALTER TABLE data_sources
    ADD CONSTRAINT data_sources_format_check
    CHECK (format IN ('rss', 'cisa_kev_json', 'github_advisories_json', 'nvd_json', 'hibp_breaches_json', 'hacker_news_json'));

INSERT INTO data_sources (
    id,
    name,
    address,
    license_name,
    license_url,
    permitted_use,
    attribution,
    content_policy,
    poll_interval_seconds,
    enabled,
    format
) VALUES
    (
        'cisa-ics-advisories',
        'CISA Industrial Control Systems Advisories',
        'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
        'U.S. federal government work. TLP:CLEAR, subject to copyright controls.',
        'https://www.cisa.gov/notification',
        'Store and display headlines and original links only. Do not use CISA or DHS logos or imply endorsement.',
        'Source: CISA. No endorsement by CISA or DHS is implied. Terms: https://www.cisa.gov/notification',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'cisa-ics-medical-advisories',
        'CISA Industrial Control Systems Medical Advisories',
        'https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml',
        'U.S. federal government work. TLP:CLEAR, subject to copyright controls.',
        'https://www.cisa.gov/notification',
        'Store and display headlines and original links only. Do not use CISA or DHS logos or imply endorsement.',
        'Source: CISA. No endorsement by CISA or DHS is implied. Terms: https://www.cisa.gov/notification',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'cisa-news',
        'CISA News',
        'https://www.cisa.gov/news.xml',
        'U.S. federal government work. TLP:CLEAR, subject to copyright controls.',
        'https://www.cisa.gov/notification',
        'Store and display headlines and original links only. Do not use CISA or DHS logos or imply endorsement.',
        'Source: CISA. No endorsement by CISA or DHS is implied. Terms: https://www.cisa.gov/notification',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'cisa-blog',
        'CISA Blog',
        'https://www.cisa.gov/cisa/blog.xml',
        'U.S. federal government work. TLP:CLEAR, subject to copyright controls.',
        'https://www.cisa.gov/notification',
        'Store and display headlines and original links only. Do not use CISA or DHS logos or imply endorsement.',
        'Source: CISA. No endorsement by CISA or DHS is implied. Terms: https://www.cisa.gov/notification',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'fbi-ic3-psa',
        'FBI IC3 Public Service Announcements',
        'https://www.ic3.gov/PSA/RSS',
        'U.S. federal government work. IC3 publishes no separate reuse terms.',
        'https://www.ic3.gov/',
        'Store and display headlines and original links only. Do not use FBI or IC3 logos or seals or imply endorsement.',
        'Source: FBI Internet Crime Complaint Center (IC3). No endorsement by the FBI is implied.',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'fbi-ic3-csa',
        'FBI IC3 Cybersecurity Advisories',
        'https://www.ic3.gov/CSA/RSS',
        'U.S. federal government work. IC3 publishes no separate reuse terms.',
        'https://www.ic3.gov/',
        'Store and display headlines and original links only. Joint advisories may include co-sealed third-party content. Do not use FBI or IC3 logos or seals or imply endorsement.',
        'Source: FBI Internet Crime Complaint Center (IC3). No endorsement by the FBI is implied.',
        'headline_link', 3600, true, 'rss'
    ),
    (
        'nvd-critical-cves',
        'NVD Critical CVEs',
        'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'NVD API Terms of Use',
        'https://nvd.nist.gov/developers/terms-of-use',
        'Use of the NVD API with the required notice. This collector requests only CVEs with a CVSS v3 critical rating published in the last 72 hours, once per hour without an API key, and stores only a headline built from the CVE ID and the start of its description, with a link to the NVD record.',
        'Source: NVD. Headline shortened from the CVE description. This product uses the NVD API but is not endorsed or certified by the NVD.',
        'headline_link', 3600, true, 'nvd_json'
    ),
    (
        'hibp-breaches',
        'Have I Been Pwned Breaches',
        'https://haveibeenpwned.com/api/v3/breaches',
        'Creative Commons Attribution 4.0 International (CC BY 4.0)',
        'https://haveibeenpwned.com/API/v3#License',
        'Reuse under CC BY 4.0 with attribution and a link to haveibeenpwned.com on every surface. The unauthenticated breach catalog needs no key. This collector stores only a headline built from the breach name and account count, for breaches added in the last 30 days; fabricated breaches and spam lists are skipped.',
        'Source: Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0. Headline built from the breach name and account count.',
        'headline_link', 3600, true, 'hibp_breaches_json'
    ),
    (
        'hacker-news',
        'Hacker News',
        'https://hacker-news.firebaseio.com/v0/topstories.json',
        'Hacker News API (no content license; API repository is MIT licensed)',
        'https://github.com/HackerNews/API',
        'Titles and links only, no comments or text. This collector reads the top 100 stories once per hour and keeps only titles that match security keywords.',
        'Via Hacker News (https://news.ycombinator.com). Title and link only.',
        'headline_link', 3600, true, 'hacker_news_json'
    )
ON CONFLICT (id) DO NOTHING;
