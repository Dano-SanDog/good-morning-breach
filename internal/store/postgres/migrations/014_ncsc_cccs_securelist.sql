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
    enabled
) VALUES
    (
        'uk-ncsc',
        'UK NCSC',
        'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
        'Open Government Licence v3.0',
        'https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions',
        'Reuse under the Open Government Licence v3.0, excluding third-party material, credited images, and logos. Do not imply NCSC endorsement. This collector stores only headlines and links.',
        'Contains public sector information licensed under the Open Government Licence v3.0. Source: UK NCSC. No endorsement by the NCSC is implied. Terms: https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions',
        'headline_link',
        3600,
        true
    ),
    (
        'cccs-alerts-advisories',
        'Canadian Centre for Cyber Security Alerts and Advisories',
        'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en',
        'Canada.ca Terms and Conditions (non-commercial reproduction)',
        'https://www.canada.ca/en/transparency/terms.html',
        'Non-commercial reproduction only, with the complete title and a link to the original. Do not use Cyber Centre names or graphics to suggest endorsement. This collector stores only headlines and links.',
        'Source: Canadian Centre for Cyber Security. This is a copy of the version available at the linked original. No endorsement is implied. Terms: https://www.canada.ca/en/transparency/terms.html',
        'headline_link',
        3600,
        true
    ),
    (
        'cccs-news-events-guidance',
        'Canadian Centre for Cyber Security News, Events and Guidance',
        'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=news_events_guidance&lang=en',
        'Canada.ca Terms and Conditions (non-commercial reproduction)',
        'https://www.canada.ca/en/transparency/terms.html',
        'Non-commercial reproduction only, with the complete title and a link to the original. Do not use Cyber Centre names or graphics to suggest endorsement. This collector stores only headlines and links.',
        'Source: Canadian Centre for Cyber Security. This is a copy of the version available at the linked original. No endorsement is implied. Terms: https://www.canada.ca/en/transparency/terms.html',
        'headline_link',
        3600,
        true
    ),
    (
        'kaspersky-securelist',
        'Kaspersky Securelist',
        'https://securelist.com/feed/',
        'Securelist Terms of Use (republication without modification, with credit)',
        'https://securelist.com/terms-of-use/',
        'Republication only without modification, with an active link and a Securelist blog credit. No summaries or rewrites. This collector stores only headlines and links.',
        'Securelist blog. Source: Kaspersky Securelist. Terms: https://securelist.com/terms-of-use/',
        'headline_link',
        3600,
        true
    )
ON CONFLICT (id) DO NOTHING;
