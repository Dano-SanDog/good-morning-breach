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
    'eff-deeplinks',
    'EFF Deeplinks',
    'https://www.eff.org/rss/updates.xml',
    'Creative Commons Attribution 4.0 International (CC BY 4.0) for original EFF material',
    'https://www.eff.org/copyright',
    'Reuse original EFF material under CC BY 4.0. Third-party material is excluded. This collector stores only headlines and original links.',
    'Source: EFF, CC BY 4.0 for original EFF material. Copyright: https://www.eff.org/copyright',
    'headline_link',
    3600,
    true
) ON CONFLICT (id) DO NOTHING;
