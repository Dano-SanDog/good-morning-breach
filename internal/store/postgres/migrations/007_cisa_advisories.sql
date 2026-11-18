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
) VALUES (
    'cisa-cybersecurity-advisories',
    'CISA Cybersecurity Advisories',
    'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    'U.S. federal government work. TLP:CLEAR, subject to copyright controls.',
    'https://www.cisa.gov/notification',
    'Store and display headlines and original links only. Feed entries may include co-sealed third-party content. Do not use CISA or DHS logos or imply endorsement.',
    'Source: CISA. No endorsement by CISA or DHS is implied. Terms: https://www.cisa.gov/notification',
    'headline_link',
    3600,
    true
) ON CONFLICT (id) DO NOTHING;
