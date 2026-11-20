ALTER TABLE data_sources
    ADD COLUMN format text NOT NULL DEFAULT 'rss'
    CHECK (format IN ('rss', 'cisa_kev_json', 'github_advisories_json'));

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
        'cisa-kev',
        'CISA Known Exploited Vulnerabilities',
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'CC0 1.0 Universal',
        'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt',
        'The KEV catalog is dedicated to the public domain under CC0 1.0. Do not use CISA or DHS logos or seals or imply endorsement. This collector stores only a headline built from the CVE ID, vendor, product, and vulnerability name, and a link to the NVD entry. Only entries added in the last 30 days are collected.',
        'Source: CISA Known Exploited Vulnerabilities catalog (CC0 1.0). No endorsement by CISA or DHS is implied. License: https://www.cisa.gov/sites/default/files/licenses/kev/license.txt',
        'headline_link',
        3600,
        true,
        'cisa_kev_json'
    ),
    (
        'github-advisory-database',
        'GitHub Advisory Database',
        'https://api.github.com/advisories?type=reviewed&sort=published&direction=desc&per_page=50',
        'Creative Commons Attribution 4.0 International (CC BY 4.0)',
        'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md',
        'Reuse under CC BY 4.0 with attribution, marking changes. This collector stores only the advisory summary as a headline, with a link to the GHSA page. The unauthenticated API is polled at most hourly.',
        'Source: GitHub Advisory Database, CC BY 4.0. Headline shortened or reformatted from the advisory summary. Link: https://github.com/advisories',
        'headline_link',
        3600,
        true,
        'github_advisories_json'
    )
ON CONFLICT (id) DO NOTHING;
