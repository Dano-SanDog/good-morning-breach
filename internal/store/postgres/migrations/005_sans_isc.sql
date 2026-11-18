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
    'sans-internet-storm-center',
    'SANS Internet Storm Center',
    'https://isc.sans.edu/rssfeed.xml',
    'Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)',
    'https://creativecommons.org/licenses/by-nc-sa/4.0/',
    'Non-commercial display is permitted. Shared adaptations and summaries must carry CC BY-NC-SA 4.0 and note changes. This collector stores only the headline and link.',
    '© SANS Internet Storm Center, CC BY-NC-SA 4.0. Source: https://isc.sans.edu/',
    'headline_link',
    1800,
    true
) ON CONFLICT (id) DO NOTHING;
